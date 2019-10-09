/* The MIT License (MIT)
 * 
 * Copyright (c) 2017 Monetra Technologies, LLC.
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

#ifndef __M_IO_MFI_EA_H__
#define __M_IO_MFI_EA_H__

#import <CoreFoundation/CoreFoundation.h>
#import <ExternalAccessory/ExternalAccessory.h>

@interface M_io_mfi_ea : NSObject <EAAccessoryDelegate, NSStreamDelegate>

/* Initializer */
+ (id)m_io_mfi_ea: (NSString *)protocol handle:(M_io_handle_t *)handle serialnum:(NSString *)serialnum;

/* Stardard init/dealloc functions */
- (id)init: (NSString *)protocol handle:(M_io_handle_t *)handle serialnum:(NSString *)serialnum;
- (void)dealloc;

/* Start connecting */
- (void)connect;

/* Initiate a close */
- (void)close;

/* Trigger the iOS event system to try to write data */
- (void)write_data_buffered;

@end

#endif /* __M_IO_MFI_EA_H__ */
