// Licensed to `the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package amcl

import (
	"fmt"
)

const (
	wrongPin = -19
)

// Error is for errors returned from AMCL wrappers
type Error struct {
	code int
}

func (err *Error) Error() string {
	return fmt.Sprintf("amcl: return code %v", err.code)
}

func newError(code int) error {
	if code == 0 {
		return nil
	}

	return &Error{code}
}

// IsWrongPin returns true if the err is Wrong PIN
func IsWrongPin(err error) bool {
	amclError, ok := err.(*Error)
	return ok && amclError.code == wrongPin
}
