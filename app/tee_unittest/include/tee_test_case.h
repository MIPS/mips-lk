/*
 * Copyright (C) 2016 Imagination Technologies Ltd.
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
#ifndef _TEEUNITTEST_INCLUDE_TEETESTCASE_H_
#define _TEEUNITTEST_INCLUDE_TEETESTCASE_H_

static uint _tests_total  = 0; /* Number of conditions checked */
static uint _tests_failed = 0; /* Number of conditions failed  */

/*
 * BEGIN_TEST_CASE and END_TEST_CASE define a function that calls
 * RUN_TEST.
 */
#define BEGIN_TEST_CASE(case_name)              \
    bool case_name(void)                        \
    {                                           \
    bool all_success = true;                    \
    printf("\nCASE %-59s [STARTED] \n", #case_name); \
    _tests_total  = 0;                          \
    _tests_failed = 0;


#define DEFINE_REGISTER_TEST_CASE(case_name)                            \
    static void _register_##case_name(void)                             \
    {                                                                   \
        unittest_register_test_case(&_##case_name##_element);           \
    }                                                                   \
    void (*_register_##case_name##_ptr)(void) __SECTION(".ctors") =     \
        _register_##case_name;

#define END_TEST_CASE(case_name)                                        \
    if (all_success) {                                                  \
        printf("CASE %-59s [PASSED]\n", #case_name);                    \
    } else {                                                            \
        printf("CASE %-59s [FAILED] %d tests out of %d\n", #case_name,  \
                _tests_failed, _tests_total);                           \
        printf("CASE %-59s [FAILED]\n", #case_name);                    \
    }                                                                   \
        return all_success;                                             \
    }                                                                   \
    struct test_case_element _##case_name##_element = {                 \
        .next = NULL,                                                   \
        .failed_next = NULL,                                            \
        .name = #case_name,                                             \
        .test_case = case_name,                                         \
    };

    // DEFINE_REGISTER_TEST_CASE(case_name);
#define RUN_TEST(test)                                  \
    printf("Running test \t\t%s \n", #test);            \
    _tests_total++;                                     \
    if (!test()) {                                      \
         all_success = false;                           \
    }

#define TEE_TEST_BEGIN(name)                            \
    bool _all_ok = true;                                \
    const char *_test = name;


#define TEE_TEST_END                                    \
{                                                       \
    if (_all_ok) {                                      \
        printf("\t\t\t%s: PASSED\n", _test);            \
    } else {                                            \
        printf("\t\t\t%s: FAILED\n", _test);            \
        _tests_failed++;                                \
    }                                                   \
    return _all_ok;                                     \
}

/* EXPECT_EQ macro doesn't do exactly what we need */
#define TEE_EXPECT_EQ(expected, actual, msg)            \
{                                                       \
    typeof(actual) _e = expected;                       \
    typeof(actual) _a = actual;                         \
    if (_e != _a) {                                     \
        printf("%s: expected " #expected " (%x), "      \
            "actual " #actual " (%x)\n",                \
            msg, (int)_e, (int)_a);                     \
        _all_ok = false;                                \
    }                                                   \
}

#define TEE_EXPECT_NOT_EQ(expected, actual, msg)        \
{                                                       \
    typeof(actual) _e = expected;                       \
    typeof(actual) _a = actual;                         \
    if (_e == _a) {                                     \
        printf("%s: not expected " #expected " (%x), "  \
            "actual " #actual " (%x)\n",                \
            msg, (int)_e, (int)_a);                     \
        _all_ok = false;                                \
    }                                                   \
}

#define TEE_EXPECT_GT(expected, actual, msg)            \
{                                                       \
    typeof(actual) _e = expected;                       \
    typeof(actual) _a = actual;                         \
    if (_e <= _a) {                                     \
        printf("%s: expected " #expected " (%d), "      \
            "actual " #actual " (%d)\n",                \
            msg, (int)_e, (int)_a);                     \
        _all_ok = false;                                \
    }                                                   \
}


#define TEE_EXPECT_BUFFER(exp_p, exp_l, got_p, got_l)                       \
{                                                                           \
    if (exp_l != got_l) {                                                   \
        printf("Buffer %s got unnexpected length, exp = %ld, got %ld\n",    \
               #got_p, (long)exp_l, (long)got_l);                           \
        _all_ok = false;                                                    \
    }                                                                       \
    if (memcmp(exp_p, got_p, exp_l)) {                                      \
        printf("Buffer %s got unnexpected content\n", #got_p);              \
        _all_ok = false;                                                    \
    }                                                                       \
}

#endif
