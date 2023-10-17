#! /usr/bin/env python3

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# usage example:
# for x in ../os_ken/tests/unit/ofproto/json/**/*.json;do echo $x;./normalize_json.py < $x > xx&& mv xx $x;done

import json
import sys

j = sys.stdin.read()
d = json.loads(j)
print json.dumps(d, ensure_ascii=True, indent=3, sort_keys=True)
