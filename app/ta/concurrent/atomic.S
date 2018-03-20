/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <asm.h>

/* uint32_t atomic_inc(uint32_t *v); */
FUNCTION(atomic_inc)
    lw      $v0, 0($a0)
    addiu 	$v0, $v0, 1
    sw 		$v0, 0($a0)
    jr      $ra
    nop

/* uint32_t atomic_dec(uint32_t *v); */
FUNCTION(atomic_dec)
    lw      $v0, 0($a0)
    addiu 	$v0, $v0, -1
    sw 		$v0, 0($a0)
    jr      $ra
    nop
