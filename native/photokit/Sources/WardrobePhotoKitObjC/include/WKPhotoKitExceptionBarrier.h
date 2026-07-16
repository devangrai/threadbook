#ifndef WK_PHOTOKIT_EXCEPTION_BARRIER_H
#define WK_PHOTOKIT_EXCEPTION_BARRIER_H

#include <stdbool.h>

typedef void (^wk_photokit_objc_block_t)(void);

bool wk_photokit_objc_perform(wk_photokit_objc_block_t block);
bool wk_photokit_objc_test_exception_containment(void);

#endif
