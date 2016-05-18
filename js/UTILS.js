/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

/**
 * @fileoverview Utilities
 */

/**
 * Check whether an input is a Byte-array.
 * 
 * @param {byte-array}
 *            bytes - any byte-array
 * @return {boolean} true/false
 */
function isBytes(bytes) {
	function isByte(num) {
		// is Integer s.t. 0 <= num < 256?
		if (!(typeof(num) === 'number') || !(Math.round(num) === num) || (num < 0) || (256 <= num)) {
			return false;
		} else {
			return true;
		}
	}

	if (Array.isArray(bytes) && bytes.every(isByte)) {
		return true;
	} else {
		return false;
	}
}

/**
 * Convert an Unsigned Integer to a Byte-array.
 * 
 * @param {integer}
 *            num - an integer greater than or equal to 0
 * @return {byte-array} converted data
 */
function uint2bytes(num) {
	// is Unsigned Integer?
	if (!(typeof(num) === 'number') || !(Math.round(num) === num) || (num < 0)) {
		return null;
	}

	if (num === 0) {
		return [ 0 ];
	}

	var bytes = [];
	while (num > 0) {
		var byte = num % 256;
		bytes.push(byte);

		num = (num - byte) / 256;
	}
	return bytes;
}

/**
 * Convert an Unsigned Integer to a fixed-length Byte-array with zero-fill.
 * 
 * @param {integer}
 *            num - an integer greater than or equal to 0
 * @return {byte-array} converted data
 */
function uint2fixedLengthBytes(num, size) {
	var bytes = uint2bytes(num);
	if (bytes === null) {
		return null;
	}

	for (var i = size - bytes.length; i > 0; i--) {
		bytes.push(0);
	}
	return bytes;
}

/**
 * Convert a Byte-array to an Unsigned Integer.
 * 
 * @param {byte-array}
 *            bytes - an integer represented by a byte-array
 * @return {integer} converted data
 */
function bytes2uint(bytes) {
	// is Byte Array?
	if (!isBytes(bytes)) {
		return null;
	}

	var num = 0;
	for (var i = bytes.length - 1; i >= 0; i--) {
		num = 256 * num + bytes[i];
	}
	return num;
}

/**
 * Convert a String to Byte-array. The encording of the input is only ASCII.
 * 
 * @param {string}
 *            str - an ASCII string
 * @return {byte-array} converted data
 */
function str2bytes(str) {
	// is String?
	if (typeof str !== 'string') {
		return null;
	}

	var bytes = [];
	for (var i = 0; i < str.length; i++) {
		bytes.push(str.charCodeAt(i));
	}
	return bytes;
}

/**
 * Convert a String to a Byte-array. The Byte Array of the string is only ASCII
 * code.
 * 
 * @param {byte-array}
 *            bytes - byte array of the ASCII string
 * @return {string} converted data
 */
function bytes2str(bytes) {
	// is Byte Array?
	if (!isBytes(bytes)) {
		return null;
	}

	var str = '';
	for (var i = 0; i < bytes.length; i++) {
		str += String.fromCharCode(bytes[i]);
	}
	return str;
}

/**
 * Convert a Hex-string to a Byte-array.
 * 
 * @param {hex-string}
 *            str - a hex-string
 * @return {byte-array} converted data
 */
function hexstr2bytes(str) {
	// is Hex String?
	var re = /[^0-9a-f]+/i;
	if ((typeof str !== 'string') || (re.test(str))) {
		return null;
	}

	// 0-fill
	if (str.length % 2 !== 0) {
		str = '0' + str;
	}

	var bytes = [];
	for (var i = 0; i < str.length; i += 2) {
		bytes.push(parseInt(str.substr(i, 2), 16));
	}
	return bytes;
}

/**
 * Convert a Byte-array to a Hex-string.
 * 
 * @param {byte-array}
 *            bytes - byte array of the hex-string
 * @return {hex-string} converted data
 */
function bytes2hexstr(bytes) {
	// is Byte Array?
	if (!isBytes(bytes)) {
		return null;
	}

	var str = '';
	for (var i = 0; i < bytes.length; i++) {
		var tmp = bytes[i].toString(16);
		str = str + (tmp.length === 1 ? '0' + tmp : tmp);
	}
	return str;
}

/**
 * Hash an ASCII string into a SHA256 byte-array.
 * 
 * @param {string}
 *            str - any ASCII string
 * @return {byte-array} hashed data
 */
function hashIntoBytesFromString(str) {
	var bytes = str2bytes(str);
	if (bytes === null) {
		return null;
	}

	var h = new HASH();
	h.init();
	h.process_array(bytes);
	return h.hash();
}

/**
 * Hash a Byte-array into a SHA256 byte-array.
 * 
 * @param {byte-array}
 *            bytes - any byte-array
 * @return {byte-array} hashed data
 */
function hashIntoBytesFromBytes(bytes) {
	// is Byte Array?
	if (!isBytes(bytes)) {
		return null;
	}

	var h = new HASH();
	h.init();
	h.process_array(bytes);
	return h.hash();
}

/**
 * Reverse a byte-array.
 * 
 * @param {byte-array}
 *            bytes - a byte-array
 * @return {byte-array} reversed byte-array of the input
 * 
 * @example r = reverseBytes([1, 2, 3, 4, 5]); // r => [5, 4, 3, 2, 1]
 */
function reverseBytes(bytes) {
	// is Byte Array?
	if (!isBytes(bytes)) {
		return null;
	}

	var rBytes = [];
	for (var i = bytes.length - 1; i >= 0; i--) {
		rBytes.push(bytes[i]);
	}
	return rBytes;
}
