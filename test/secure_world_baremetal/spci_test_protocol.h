/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
	FF_A_MEMORY_SHARE = 1,
	FF_A_UNDEFINED
};
