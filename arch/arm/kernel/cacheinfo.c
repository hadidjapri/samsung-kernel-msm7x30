/*
 *  ARM cacheinfo support
 *
 *  Copyright (C) 2013 ARM Ltd.
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/smp.h>

#include <asm/processor.h>

enum cache_type {
	CACHE_TYPE_NOCACHE = 0,
	CACHE_TYPE_INST = 1,
	CACHE_TYPE_DATA = 2,
	CACHE_TYPE_SEPARATE = 3,
	CACHE_TYPE_UNIFIED = 4,
};

struct cache_info {
	enum cache_type type; /* data, inst or unified */
	unsigned int level;
	unsigned int coherency_line_size; /* cache line size  */
	unsigned int number_of_sets; /* no. of sets per way */
	unsigned int ways_of_associativity; /* no. of ways */
	unsigned int size; /* total cache size */
};

struct cpu_cacheinfo {
	struct cache_info info;
	struct device_node *of_node;	/* cpu if no explicit cache node */
	cpumask_t shared_cpu_map;
};

static DEFINE_PER_CPU(unsigned int, num_cache_leaves);
static DEFINE_PER_CPU(unsigned int, num_cache_levels);
#define cache_leaves(cpu)      per_cpu(num_cache_leaves, cpu)
#define cache_levels(cpu)      per_cpu(num_cache_levels, cpu)

#if __LINUX_ARM_ARCH__ < 7 /* pre ARMv7 */

#define MAX_CACHE_LEVEL		1	/* Only 1 level supported */
#define CTR_CTYPE_SHIFT		24
#define CTR_CTYPE_MASK		(1 << CTR_CTYPE_SHIFT)

static inline unsigned int get_ctr(void)
{
	unsigned int ctr;
	asm volatile ("mrc p15, 0, %0, c0, c0, 1" : "=r" (ctr));
	return ctr;
}

static enum cache_type get_cache_type(int level)
{
	if (level > MAX_CACHE_LEVEL)
		return CACHE_TYPE_NOCACHE;
	return get_ctr() & CTR_CTYPE_MASK ?
		CACHE_TYPE_SEPARATE : CACHE_TYPE_UNIFIED;
}

/*
 *  +---------------------------------+
 *  | 9  8  7  6 | 5  4  3 | 2 | 1  0 |
 *  +---------------------------------+
 *  |    size    |  assoc  | m |  len |
 *  +---------------------------------+
 * linelen        = 1 << (len + 3)
 * multiplier     = 2 + m
 * nsets          = 1 << (size + 6 - assoc - len)
 * associativity  = multiplier << (assoc - 1)
 * cache_size     = multiplier << (size + 8)
 */
#define CTR_LINESIZE_MASK	0x3
#define CTR_MULTIPLIER_SHIFT	2
#define CTR_MULTIPLIER_MASK	0x1
#define CTR_ASSOCIAT_SHIFT	3
#define CTR_ASSOCIAT_MASK	0x7
#define CTR_SIZE_SHIFT		6
#define CTR_SIZE_MASK		0xF
#define CTR_DCACHE_SHIFT	12

static void __cpu_cache_info_init(enum cache_type type,
					struct cache_info *this_leaf)
{
	unsigned int size, multiplier, assoc, len, tmp = get_ctr();

	if (type == CACHE_TYPE_DATA)
		tmp >>= CTR_DCACHE_SHIFT;

	len = tmp & CTR_LINESIZE_MASK;
	size = (tmp >> CTR_SIZE_SHIFT) & CTR_SIZE_MASK;
	assoc = (tmp >> CTR_ASSOCIAT_SHIFT) & CTR_ASSOCIAT_MASK;
	multiplier = ((tmp >> CTR_MULTIPLIER_SHIFT) & CTR_MULTIPLIER_MASK) + 2;

	this_leaf->type = type;
	this_leaf->coherency_line_size = 1 << (len + 3);
	this_leaf->number_of_sets = 1 << (size + 6 - assoc - len);
	this_leaf->ways_of_associativity = multiplier << (assoc - 1);
	this_leaf->size = multiplier << (size + 8);
}

#else /* ARMv7 */

#define MAX_CACHE_LEVEL			7	/* Max 7 level supported */
/* Ctypen, bits[3(n - 1) + 2 : 3(n - 1)], for n = 1 to 7 */
#define CLIDR_CTYPE_SHIFT(level)	(3 * (level - 1))
#define CLIDR_CTYPE_MASK(level)		(7 << CLIDR_CTYPE_SHIFT(level))
#define CLIDR_CTYPE(clidr, level)	\
	(((clidr) & CLIDR_CTYPE_MASK(level)) >> CLIDR_CTYPE_SHIFT(level))

static inline enum cache_type get_cache_type(int level)
{
	unsigned int clidr;
	if (level > MAX_CACHE_LEVEL)
		return CACHE_TYPE_NOCACHE;
	asm volatile ("mrc p15, 1, %0, c0, c0, 1" : "=r" (clidr));
	return CLIDR_CTYPE(clidr, level);
}

/*
 * NumSets, bits[27:13] - (Number of sets in cache) - 1
 * Associativity, bits[12:3] - (Associativity of cache) - 1
 * LineSize, bits[2:0] - (Log2(Number of words in cache line)) - 2
 */
#define CCSIDR_LINESIZE_MASK	0x7
#define CCSIDR_ASSOCIAT_SHIFT	3
#define CCSIDR_ASSOCIAT_MASK	0x3FF
#define CCSIDR_NUMSETS_SHIFT	13
#define CCSIDR_NUMSETS_MASK	0x7FF

/*
 * Which cache CCSIDR represents depends on CSSELR value
 * Make sure no one else changes CSSELR during this
 * smp_call_function_single prevents preemption for us
 */
static inline u32 get_ccsidr(u32 csselr)
{
	u32 ccsidr;

	/* Put value into CSSELR */
	asm volatile ("mcr p15, 2, %0, c0, c0, 0" : : "r" (csselr));
	isb();
	/* Read result out of CCSIDR */
	asm volatile ("mrc p15, 1, %0, c0, c0, 0" : "=r" (ccsidr));

	return ccsidr;
}

static void __cpu_cache_info_init(enum cache_type type,
					struct cache_info *this_leaf)
{
	bool is_InD = type & CACHE_TYPE_INST;
	u32 tmp = get_ccsidr((this_leaf->level - 1) << 1 | is_InD);

	this_leaf->type = type;
	this_leaf->coherency_line_size =
	    (1 << ((tmp & CCSIDR_LINESIZE_MASK) + 2)) * 4;
	this_leaf->number_of_sets =
	    ((tmp >> CCSIDR_NUMSETS_SHIFT) & CCSIDR_NUMSETS_MASK) + 1;
	this_leaf->ways_of_associativity =
	    ((tmp >> CCSIDR_ASSOCIAT_SHIFT) & CCSIDR_ASSOCIAT_MASK) + 1;
	this_leaf->size = this_leaf->number_of_sets *
	    this_leaf->coherency_line_size * this_leaf->ways_of_associativity;
}

#endif

/* pointer to cpu_cacheinfo array (for each cache leaf) */
static DEFINE_PER_CPU(struct cpu_cacheinfo *, ci_cpu_cache_info);
#define per_cpu_cacheinfo(cpu)	 (per_cpu(ci_cpu_cache_info, cpu))
#define CPU_CACHEINFO_IDX(cpu, idx)    (&(per_cpu_cacheinfo(cpu)[idx]))

#ifdef CONFIG_OF
static int cache_setup_of_node(unsigned int cpu)
{
	struct device_node *np;
	struct cpu_cacheinfo *this_leaf;
	struct device *cpu_dev = get_cpu_device(cpu);
	int index = 0;

	if (!cpu_dev) {
		pr_err("No cpu device for CPU %d\n", cpu);
		return -ENODEV;
	}
	np = cpu_dev->of_node;
	if (!np) {
		pr_err("Failed to find cpu%d device node\n", cpu);
		return -ENOENT;
	}

	while (np && index < cache_leaves(cpu)) {
		this_leaf = CPU_CACHEINFO_IDX(cpu, index);
		if (this_leaf->info.level != 1)
			np = of_find_next_cache_node(np);
		else
			np = of_node_get(np);/* cpu node itself */
		this_leaf->of_node = np;
		index++;
	}
	return 0;
}
static inline bool cache_leaves_are_shared(struct cpu_cacheinfo *this_leaf,
					struct cpu_cacheinfo *sib_leaf)
{
	return sib_leaf->of_node == this_leaf->of_node;
}
#else
static inline int cache_setup_of_node(unsigned int cpu) { return 0; }
static inline bool cache_leaves_are_shared(struct cpu_cacheinfo *this_leaf,
					struct cpu_cacheinfo *sib_leaf)
{
	/*
	 * For non-DT systems, assume unique level 1 cache,
	 * system-wide shared caches for all other levels
	 */
	return !(this_leaf->info.level == 1);
}
#endif

static int cache_add_cpu_shared_map(unsigned int cpu)
{
	struct cpu_cacheinfo *this_leaf, *sib_leaf;
	int ret, index;

	ret = cache_setup_of_node(cpu);
	if (ret)
		return ret;

	for (index = 0; index < cache_leaves(cpu); index++) {
		int i;
		this_leaf = CPU_CACHEINFO_IDX(cpu, index);
		cpumask_set_cpu(cpu, &this_leaf->shared_cpu_map);

		for_each_online_cpu(i) {
			if (i == cpu || !per_cpu_cacheinfo(i))
				continue;/* skip if itself or no cacheinfo */
			sib_leaf = CPU_CACHEINFO_IDX(i, index);
			if (cache_leaves_are_shared(this_leaf, sib_leaf)) {
				cpumask_set_cpu(cpu, &sib_leaf->shared_cpu_map);
				cpumask_set_cpu(i, &this_leaf->shared_cpu_map);
			}
		}
	}

	return 0;
}

static void cache_remove_cpu_shared_map(unsigned int cpu)
{
	struct cpu_cacheinfo *this_leaf, *sib_leaf;
	int sibling, index;

	for (index = 0; index < cache_leaves(cpu); index++) {
		this_leaf = CPU_CACHEINFO_IDX(cpu, index);
		for_each_cpu(sibling, &this_leaf->shared_cpu_map) {
			if (sibling == cpu) /* skip itself */
				continue;
			sib_leaf = CPU_CACHEINFO_IDX(sibling, index);
			cpumask_clear_cpu(cpu, &sib_leaf->shared_cpu_map);
			cpumask_clear_cpu(sibling, &this_leaf->shared_cpu_map);
		}
		of_node_put(this_leaf->of_node);
	}
}

static void init_cache_level(unsigned int cpu)
{
	unsigned int ctype, level = 1, leaves = 0;

	do {
		ctype = get_cache_type(level);
		if (ctype == CACHE_TYPE_NOCACHE)
			break;
		/* Separate instruction and data caches */
		leaves += (ctype == CACHE_TYPE_SEPARATE) ? 2 : 1;
	} while (++level <= MAX_CACHE_LEVEL);
	cache_levels(cpu) = level - 1;
	cache_leaves(cpu) = leaves;
}

static void cpu_cache_info_init(unsigned int cpu, enum cache_type type,
				unsigned int level, unsigned int index)
{
	struct cpu_cacheinfo *this_leaf;

	this_leaf = CPU_CACHEINFO_IDX(cpu, index);
	this_leaf->info.level = level;
	__cpu_cache_info_init(type, &this_leaf->info);
}

static void init_cache_leaves(unsigned int cpu)
{
	int level, idx;
	enum cache_type type;

	for (idx = 0, level = 1; level <= cache_levels(cpu) &&
					idx < cache_leaves(cpu);) {
		type = get_cache_type(level);

		if (type == CACHE_TYPE_SEPARATE) {
			cpu_cache_info_init(cpu, CACHE_TYPE_DATA, level, idx++);
			cpu_cache_info_init(cpu, CACHE_TYPE_INST,
							level++, idx++);
		} else {
			cpu_cache_info_init(cpu, type, level++, idx++);
		}
	}
}

static int detect_cache_attributes(unsigned int cpu)
{
	int ret;

	init_cache_level(cpu);
	if (cache_leaves(cpu) == 0)
		return -ENOENT;

	per_cpu_cacheinfo(cpu) =
	    kzalloc(sizeof(struct cpu_cacheinfo) * cache_leaves(cpu),
		    GFP_KERNEL);
	if (per_cpu_cacheinfo(cpu) == NULL)
		return -ENOMEM;

	init_cache_leaves(cpu);
	ret = cache_add_cpu_shared_map(cpu);
	if (ret) {
		kfree(per_cpu_cacheinfo(cpu));
		per_cpu_cacheinfo(cpu) = NULL;
	}

	return ret;
}

static void free_cache_attributes(unsigned int cpu)
{
	cache_remove_cpu_shared_map(cpu);

	kfree(per_cpu_cacheinfo(cpu));
	per_cpu_cacheinfo(cpu) = NULL;
}
