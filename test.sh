#!/bin/sh

PROG=./rsa

TESTKEY_PRIV=testkey.priv
TESTKEY_PUB=testkey.pub
TMPKEY=tmpkey.priv

num_tests=0
num_passed=0

pass() {
	num_tests=$(($num_tests+1))
	num_passed=$(($num_passed+1))
	echo "PASS $1"
}

fail() {
	num_tests=$(($num_tests+1))
	echo "FAIL $1"
	shift
	while [ $# -gt 0 ]; do
		echo "$1" | awk '{print "     "$0}'
		shift
	done
}

test_bad() {
	"$PROG" "$@" > /dev/null 2>&1
	if [ $? -ne 0 ]; then
		pass "$PROG $@"
	else
		fail "$PROG $@" "should have returned an error code but didn't"
	fi
}

test_encrypt() {
	local keyfile="$1"
	local message="$2"
	local expected="$3"

	local output="$("$PROG" encrypt "$keyfile" "$message" 2>/dev/null)"
	if [ $? -eq 0 -a "$output" = "$expected" ]; then
		pass "$PROG encrypt $keyfile \"$message\""
	else
		fail "$PROG encrypt $keyfile \"$message\"" "got      $output" "expected $expected"
	fi
}

test_decrypt() {
	local keyfile="$1"
	local c="$2"
	local expected="$3"

	local output="$("$PROG" decrypt "$keyfile" "$c" 2>/dev/null | hexdump -v -e '/1 "%02x"')"
	if [ $? -eq 0 -a "$output" = "$expected" ]; then
		pass "$PROG decrypt $keyfile $c"
	else
		fail "$PROG decrypt $keyfile $c" "got (hex)      $output" "expected (hex) $expected"
	fi
}

fail_if_bad_modulus() {
	local keyfile="$1"
	local expected_numbits="$2"
	local n

	while read varname value; do
		if [ $varname = n ]; then
			n=$value
		fi
	done < $keyfile
	if [ -z "$n" ]; then
		fail "$keyfile missing modulus" "$(cat $keyfile)"
		return 1
	fi
	local numbits=$(echo "$n" | awk '{print log($0+1)/log(2)}')
	local int_numbits=$(echo "$numbits" | sed -e 's/\..*//')
	local min_numbits=$(dc -e "$expected_numbits 1 - p")
	local max_numbits=$(dc -e "$expected_numbits 1 + p")
	if [ $int_numbits -lt $min_numbits ]; then
		fail "$keyfile modulus too short ($numbits bits, wanted $expected_numbits)" "$(cat $keyfile)"
		return 1
	fi
	if [ $int_numbits -gt $max_numbits ]; then
		fail "$keyfile modulus too long ($numbits bits, wanted $expected_numbits)" "$(cat $keyfile)"
		return 1
	fi
	return 0
}

test_modulus_size() {
	local keyfile="$1"
	local numbits="$2"

	if fail_if_bad_modulus "$keyfile" "$numbits"; then
		pass "$keyfile modulus $numbits bits"
	fi
}

# Convert its argument to a hex string.
hex() {
	echo -n "$1" | hexdump -v -e '/1 "%02x"'
}

test_genkey() {
	local numbits="$1"

	for iter in $(seq 1 10); do
		"$PROG" genkey $numbits 2>/dev/null >$TMPKEY
		if ! fail_if_bad_modulus "$TMPKEY" "$numbits"; then
			return
		fi

		# Try to decrypt what we encrypted.
		local c="$("$PROG" encrypt $TMPKEY "hello world" 2>/dev/null)"
		local output="$("$PROG" decrypt $TMPKEY "$c" 2>/dev/null | hexdump -v -e '/1 "%02x"')"
		if [ "$output" != $(hex "hello world") ]; then
			fail "genkey $numbits roundtrip \"hello world\"" "$(cat $TMPKEY)"
			return
		fi
	done
	pass "genkey $numbits roundtrip"
}

# Syntax checks.
test_bad
test_bad blah
test_bad encrypt
test_bad encrypt $TESTKEY_PUB
test_bad encrypt $TESTKEY_PUB x x
test_bad decrypt
test_bad decrypt $TESTKEY_PRIV
test_bad decrypt $TESTKEY_PRIV x x
test_bad genkey
test_bad genkey 1024 x
# Nonexistent or invalid key files.
test_bad encrypt nonexistent "message"
test_bad encrypt /dev/null "message"
test_bad decrypt nonexistent 12345
test_bad decrypt /dev/null 12345
# decrypt needs a private key file.
test_bad decrypt $TESTKEY_PUB 55353720671152855484892138743556378206

test_encrypt $TESTKEY_PUB "" 0
test_encrypt $TESTKEY_PUB "0" 55353720671152855484892138743556378206
test_encrypt $TESTKEY_PUB "hello world" 64783502818557067895836504540696438999
# encrypt should be able to use a public or a private key file.
test_encrypt $TESTKEY_PRIV "" 0
test_encrypt $TESTKEY_PRIV "0" 55353720671152855484892138743556378206
test_encrypt $TESTKEY_PRIV "hello world" 64783502818557067895836504540696438999

test_decrypt $TESTKEY_PRIV 0 $(hex "")
test_decrypt $TESTKEY_PRIV 55353720671152855484892138743556378206 $(hex "0")
test_decrypt $TESTKEY_PRIV 64783502818557067895836504540696438999 $(hex "hello world")

test_modulus_size $TESTKEY_PRIV 128

test_genkey 128
test_genkey 256
test_genkey 1024

rm -f "$TMPKEY"

printf "passed %d/%d\n" $num_passed $num_tests

[ $num_passed -eq $num_tests ]
exit $?
