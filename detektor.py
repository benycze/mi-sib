#!/usr/bin/python
# -*- encoding: utf-8 -*-
"""
_name_ - _description_
Copyright (C) _year_ _author_

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import time

aktokno=time.gmtime()
pocitadlo=0
limit=5

def detect():
    global aktokno,pocitadlo,limit
    if aktokno!=int(time.time()):
        aktokno=int(time.time())
        pocitadlo=1
    else:
        pocitadlo+=1
        if pocitadlo > limit:
            print "Limit %d v okně %d překročen, aktuální stav %d"%(limit,aktokno,pocitadlo)


while True:
    detect()
    raw_input("Podrž entr a uvidíš")
