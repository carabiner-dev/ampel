// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

/*

test case:
The following reference needs to fail in a policy
if the source URI points to a policy set. If json-file.json
is a policy, then it should work fine.

{
    "source": {
        "location": {
            "uri": "git+https://github.com/example/repo@9834934873487978349789#json-file.json"
        }
    }
},



TEST CASE:

Pulling this reference needs to fail (the hash is not right):

{
            "location": {
                "uri": "git+https://github.com/puerco/lab#ampel/minimum-elements.policy.json@0f99ab885ebe8d37e1b8d9c6a0708339fd686402",
                "digest": {
                    "sha256": "ba069d6f37afff1aafa0b483949f7d05a4137cba50406875055d222fa138e99c"
                }
            }
        }

*/
