/* The MIT License (MIT)
 * 
 * Copyright (c) 2017 Main Street Softworks, Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* Implementations of log module functions that are the same for all modules.
 *
 */
#include "m_config.h"
#include <m_log_int.h>


/* ---- PROTECTED: helper functions shared between module implementations ---- */

/* log must be locked when you call this function. */
M_bool module_present_locked(M_log_t *log, M_log_module_t *module)
{
	if (M_llist_find(log->modules, module, M_LLIST_MATCH_VAL) == NULL) {
		return M_FALSE;
	} else {
		return M_TRUE;
	}
}


void module_remove_locked(M_log_t *log, M_log_module_t *module)
{
	M_llist_remove_val(log->modules, module, M_LLIST_MATCH_VAL);
}



/* ---- PUBLIC: API functions that work with all module types ---- */

M_bool M_log_module_present(M_log_t *log, M_log_module_t *module)
{
	M_bool ret;

	if (log == NULL || module == NULL) {
		return M_FALSE;
	}

	M_thread_mutex_lock(log->lock);

	ret = module_present_locked(log, module);

	M_thread_mutex_unlock(log->lock);

	return ret;
}


M_log_module_type_t M_log_module_type(M_log_t *log, M_log_module_t *module)
{
	M_log_module_type_t type;

	if (log == NULL || module == NULL) {
		return M_LOG_MODULE_NULL;
	}

	M_thread_mutex_lock(log->lock);

	if (!module_present_locked(log, module)) {
		M_thread_mutex_unlock(log->lock);
		return M_LOG_MODULE_NULL;
	}

	type = module->type;

	M_thread_mutex_unlock(log->lock);
	return type;
}


M_log_error_t M_log_module_set_accepted_tags(M_log_t *log, M_log_module_t *module, M_uint64 tags)
{
	if (log == NULL || module == NULL) {
		return M_LOG_INVALID_PARAMS;
	}

	M_thread_mutex_lock(log->lock);

	if (!module_present_locked(log, module)) {
		M_thread_mutex_unlock(log->lock);
		return M_LOG_MODULE_NOT_FOUND;
	}

	module->accepted_tags = tags;

	M_thread_mutex_unlock(log->lock);
	return M_LOG_SUCCESS;
}


M_log_error_t M_log_module_get_accepted_tags(M_log_t *log, M_log_module_t *module, M_uint64 *out_tags)
{
	if (log == NULL || module == NULL || out_tags == NULL) {
		return M_LOG_INVALID_PARAMS;
	}

	M_thread_mutex_lock(log->lock);

	if (!module_present_locked(log, module)) {
		M_thread_mutex_unlock(log->lock);
		return M_LOG_MODULE_NOT_FOUND;
	}

	*out_tags = module->accepted_tags;

	M_thread_mutex_unlock(log->lock);
	return M_LOG_SUCCESS;
}


M_log_error_t M_log_module_set_prefix(M_log_t *log, M_log_module_t *module, M_log_prefix_cb prefix_cb,
	void *prefix_thunk, M_log_destroy_cb thunk_destroy_cb)
{
	if (log == NULL || module == NULL) {
		return M_LOG_INVALID_PARAMS;
	}

	M_thread_mutex_lock(log->lock);

	if (!module_present_locked(log, module)) {
		M_thread_mutex_unlock(log->lock);
		return M_LOG_MODULE_NOT_FOUND;
	}

	module->prefix_cb               = prefix_cb;
	module->prefix_thunk            = prefix_thunk;
	module->destroy_prefix_thunk_cb = thunk_destroy_cb;

	M_thread_mutex_unlock(log->lock);
	return M_LOG_SUCCESS;
}


M_log_error_t M_log_module_set_filter(M_log_t *log, M_log_module_t *module, M_log_filter_cb filter_cb,
	void *filter_thunk, M_log_destroy_cb thunk_destroy_cb)
{
	if (log == NULL || module == NULL) {
		return M_LOG_INVALID_PARAMS;
	}

	M_thread_mutex_lock(log->lock);

	if (!module_present_locked(log, module)) {
		M_thread_mutex_unlock(log->lock);
		return M_LOG_MODULE_NOT_FOUND;
	}

	module->filter_cb               = filter_cb;
	module->filter_thunk            = filter_thunk;
	module->destroy_filter_thunk_cb = thunk_destroy_cb;

	M_thread_mutex_unlock(log->lock);
	return M_LOG_SUCCESS;
}


M_log_error_t M_log_module_reopen(M_log_t *log, M_log_module_t *module)
{
	M_log_error_t ret = M_LOG_SUCCESS;;

	if (log == NULL || module == NULL) {
		return M_LOG_INVALID_PARAMS;
	}

	M_thread_mutex_lock(log->lock);

	if (!module_present_locked(log, module)) {
		M_thread_mutex_unlock(log->lock);
		return M_LOG_MODULE_NOT_FOUND;
	}

	if (module->module_reopen_cb != NULL) {
		ret = module->module_reopen_cb(module);
	}

	M_thread_mutex_unlock(log->lock);
	return ret;
}


M_log_error_t M_log_module_remove(M_log_t *log, M_log_module_t *module)
{
	if (log == NULL || module == NULL) {
		return M_LOG_INVALID_PARAMS;
	}

	M_thread_mutex_lock(log->lock);

	module_remove_locked(log, module);

	M_thread_mutex_unlock(log->lock);

	return M_LOG_SUCCESS;
}
