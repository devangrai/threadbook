#import <Foundation/Foundation.h>

#import "WKPhotoKitExceptionBarrier.h"

bool wk_photokit_objc_perform(wk_photokit_objc_block_t block) {
  if (block == nil) {
    return false;
  }

  @try {
    block();
    return true;
  } @catch (__unused NSException *exception) {
    return false;
  }
}

bool wk_photokit_objc_test_exception_containment(void) {
  return !wk_photokit_objc_perform(^{
    [NSException raise:NSInternalInconsistencyException format:@"test"];
  });
}
