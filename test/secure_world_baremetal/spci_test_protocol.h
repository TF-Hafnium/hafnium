/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

/*
 * Table 137 (Descriptor to retrieve a donated, lent or shared memory region)
 *
 *  field name				size
 *
 *	Handle 					4
 *  Sender endpoint 		2
 *  transaction type		4
 *  tag						4
 *  #global mem region		4
 *  off global mem region	4
 *  #retrieve property desc	4
 *
 *  retrieve properties |
 *						v
 *	property[0]
 *	....
 *	property[<#retrieve property desc>-1]
 *
 */
enum message_t
{
	/*
	 * w1[31:16] -- sender endpoint ID
	 * w3 -- message_t
	 * w4 -- handle
	 * w5 -- attributes
	 */
	FF_A_INIT_SP = 1,
	FF_A_MEMORY_SHARE,
	FF_A_UNDEFINED
};
