/* SPDX-License-Identifier: GPL-2.0 */
/*
 * LiDiS Advanced Kernel Security Framework
 * 
 * Copyright (C) 2025 LiDiS Security Project
 * 
 * This header defines the LiDiS-specific kernel security enhancements
 * that extend beyond standard Linux kernel security features.
 */

#ifndef _LIDIS_SECURITY_H
#define _LIDIS_SECURITY_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/net.h>
#include <linux/skbuff.h>

/*
 * LiDiS Security Feature Flags
 */
#define LIDIS_SEC_KERNEL_GUARD		0x00000001
#define LIDIS_SEC_ENHANCED_CFI		0x00000002
#define LIDIS_SEC_ADVANCED_KASLR	0x00000004
#define LIDIS_SEC_MEMORY_PROTECTION	0x00000008
#define LIDIS_SEC_SYSCALL_FILTER	0x00000010
#define LIDIS_SEC_PROCESS_ISOLATION	0x00000020
#define LIDIS_SEC_NETWORK_SECURITY	0x00000040
#define LIDIS_SEC_FILE_INTEGRITY	0x00000080
#define LIDIS_SEC_RUNTIME_ANALYSIS	0x00000100

/*
 * LiDiS Kernel Guard - Runtime kernel integrity protection
 */
struct lidis_kernel_guard {
	u64 code_hash;
	u64 critical_data_hash;
	u32 syscall_table_hash;
	u32 lsm_hooks_hash;
	atomic_t violation_count;
	bool integrity_verified;
};

/*
 * Enhanced CFI - Extended Control Flow Integrity
 */
struct lidis_cfi_context {
	u64 *return_stack;
	u32 stack_depth;
	u32 max_depth;
	u64 function_whitelist_hash;
	bool backward_edge_enabled;
	bool hardware_cet_enabled;
};

/*
 * Advanced Memory Protection
 */
struct lidis_memory_guard {
	struct rb_root heap_chunks;
	struct rb_root stack_canaries;
	u32 heap_overflow_count;
	u32 stack_overflow_count;
	u32 use_after_free_count;
	u32 double_free_count;
	bool guard_pages_enabled;
};

/*
 * System Call Filtering and Rate Limiting
 */
#define LIDIS_SYSCALL_WHITELIST_SIZE	512
#define LIDIS_SYSCALL_RATE_WINDOW	1000	/* milliseconds */

struct lidis_syscall_filter {
	u64 whitelist[LIDIS_SYSCALL_WHITELIST_SIZE / 64];
	u32 call_counts[NR_syscalls];
	u64 last_reset_time;
	u32 rate_limit_threshold;
	bool whitelist_mode;
};

/*
 * Process Isolation Enhancement
 */
struct lidis_process_isolation {
	u32 isolation_level;
	u64 allowed_capabilities;
	u32 max_open_files;
	u32 max_memory_mb;
	u32 max_cpu_time_sec;
	bool container_hardening;
	bool namespace_protection;
};

/*
 * Network Security Context
 */
struct lidis_network_context {
	u32 packet_inspection_level;
	u32 anomaly_score;
	u64 bytes_inspected;
	u32 threats_blocked;
	bool dpi_enabled;
	bool anti_exfiltration_enabled;
};

/*
 * File System Integrity Context
 */
struct lidis_fs_integrity {
	struct rb_root monitored_files;
	u32 integrity_violations;
	u32 executable_modifications;
	u64 last_scan_time;
	bool real_time_monitoring;
};

/*
 * Runtime Security Analysis
 */
struct lidis_runtime_analysis {
	u32 behavior_score;
	u32 anomaly_count;
	u64 analysis_start_time;
	u32 threat_indicators;
	bool auto_response_enabled;
	bool behavioral_monitoring;
};

/*
 * Main LiDiS Security Context
 */
struct lidis_security_context {
	u32 enabled_features;
	struct lidis_kernel_guard kernel_guard;
	struct lidis_cfi_context cfi_context;
	struct lidis_memory_guard memory_guard;
	struct lidis_syscall_filter syscall_filter;
	struct lidis_process_isolation process_isolation;
	struct lidis_network_context network_context;
	struct lidis_fs_integrity fs_integrity;
	struct lidis_runtime_analysis runtime_analysis;
	
	/* Statistics */
	u64 security_events;
	u64 threats_detected;
	u64 threats_mitigated;
	
	/* Configuration */
	u32 security_level;		/* 1-10 scale */
	bool enforcement_mode;		/* true = enforce, false = warn */
	bool logging_enabled;
};

/*
 * Per-process LiDiS security attributes
 */
struct lidis_task_security {
	u32 security_label;
	u32 threat_score;
	u32 syscall_violations;
	u32 memory_violations;
	u32 network_violations;
	u64 creation_time;
	bool isolated;
	bool monitored;
	struct lidis_cfi_context *cfi_ctx;
};

/*
 * Global LiDiS security state
 */
extern struct lidis_security_context lidis_security;

/*
 * LiDiS Kernel Guard Functions
 */
int lidis_kernel_guard_init(void);
int lidis_kernel_guard_verify_integrity(void);
void lidis_kernel_guard_report_violation(const char *type, void *addr);
int lidis_kernel_guard_protect_syscall_table(void);
int lidis_kernel_guard_protect_lsm_hooks(void);

/*
 * Enhanced CFI Functions
 */
int lidis_cfi_init_context(struct lidis_cfi_context *ctx);
void lidis_cfi_cleanup_context(struct lidis_cfi_context *ctx);
int lidis_cfi_check_indirect_call(void *target, void *caller);
int lidis_cfi_push_return_address(struct lidis_cfi_context *ctx, u64 addr);
int lidis_cfi_pop_return_address(struct lidis_cfi_context *ctx, u64 *addr);
void lidis_cfi_violation_handler(void *target, void *caller);

/*
 * Advanced Memory Protection Functions
 */
int lidis_memory_guard_init(void);
void lidis_memory_guard_cleanup(void);
int lidis_memory_guard_check_heap_access(void *ptr, size_t size);
int lidis_memory_guard_check_stack_access(void *ptr);
void lidis_memory_guard_detect_overflow(void *ptr, size_t size);
void lidis_memory_guard_detect_use_after_free(void *ptr);
void lidis_memory_guard_detect_double_free(void *ptr);

/*
 * System Call Filtering Functions
 */
int lidis_syscall_filter_init(void);
int lidis_syscall_filter_check(long syscall_num);
int lidis_syscall_filter_add_whitelist(long syscall_num);
int lidis_syscall_filter_remove_whitelist(long syscall_num);
void lidis_syscall_filter_rate_limit_check(long syscall_num);

/*
 * Process Isolation Functions
 */
int lidis_process_isolation_init(struct task_struct *task);
void lidis_process_isolation_cleanup(struct task_struct *task);
int lidis_process_isolation_check_capability(struct task_struct *task, int cap);
int lidis_process_isolation_check_resource(struct task_struct *task, int resource);
int lidis_process_isolation_enforce_limits(struct task_struct *task);

/*
 * Network Security Functions
 */
int lidis_network_security_init(void);
int lidis_network_security_inspect_packet(struct sk_buff *skb);
int lidis_network_security_check_connection(struct sock *sk, struct sockaddr *addr);
void lidis_network_security_update_anomaly_score(u32 score);
int lidis_network_security_detect_exfiltration(struct sk_buff *skb);

/*
 * File System Integrity Functions
 */
int lidis_fs_integrity_init(void);
int lidis_fs_integrity_check_file(struct file *file);
int lidis_fs_integrity_monitor_file(const char *path);
int lidis_fs_integrity_verify_executable(struct file *file);
void lidis_fs_integrity_report_violation(const char *path, const char *type);

/*
 * Runtime Analysis Functions
 */
int lidis_runtime_analysis_init(void);
void lidis_runtime_analysis_update_behavior_score(struct task_struct *task, u32 score);
void lidis_runtime_analysis_detect_anomaly(struct task_struct *task, const char *type);
int lidis_runtime_analysis_correlate_threats(void);
int lidis_runtime_analysis_auto_response(struct task_struct *task, const char *threat);

/*
 * LSM Hook Implementations
 */
int lidis_bprm_check_security(struct linux_binprm *bprm);
int lidis_task_create(unsigned long clone_flags);
void lidis_task_free(struct task_struct *task);
int lidis_file_permission(struct file *file, int mask);
int lidis_file_open(struct file *file);
int lidis_mmap_file(struct file *file, unsigned long reqprot, 
		   unsigned long prot, unsigned long flags);
int lidis_socket_create(int family, int type, int protocol, int kern);
int lidis_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen);
int lidis_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size);

/*
 * Security Event Logging
 */
#define LIDIS_LOG_EMERG		0	/* Emergency */
#define LIDIS_LOG_ALERT		1	/* Alert */
#define LIDIS_LOG_CRIT		2	/* Critical */
#define LIDIS_LOG_ERR		3	/* Error */
#define LIDIS_LOG_WARNING	4	/* Warning */
#define LIDIS_LOG_NOTICE	5	/* Notice */
#define LIDIS_LOG_INFO		6	/* Info */
#define LIDIS_LOG_DEBUG		7	/* Debug */

void lidis_log_security_event(int level, const char *fmt, ...);

/*
 * Configuration and Statistics
 */
int lidis_security_set_feature(u32 feature, bool enable);
int lidis_security_get_statistics(struct lidis_security_context *stats);
int lidis_security_reset_statistics(void);
int lidis_security_set_level(u32 level);

/*
 * Initialization and Cleanup
 */
int lidis_security_init(void);
void lidis_security_exit(void);

/*
 * Inline helpers
 */
static inline bool lidis_feature_enabled(u32 feature)
{
	return lidis_security.enabled_features & feature;
}

static inline struct lidis_task_security *lidis_task_security(struct task_struct *task)
{
	return task->security + lidis_blob_sizes.lbs_task;
}

static inline void lidis_increment_counter(u64 *counter)
{
	if (likely(counter))
		(*counter)++;
}

/*
 * Hardware-specific optimizations
 */
#ifdef CONFIG_X86_64
#include "lidis_security_x86.h"
#endif

#ifdef CONFIG_ARM64  
#include "lidis_security_arm64.h"
#endif

#endif /* _LIDIS_SECURITY_H */