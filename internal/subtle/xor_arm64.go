// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//go:build arm64 && !purego
// +build arm64,!purego

package subtle

//go:noescape
func xorBytes(dst, a, b *byte, n int)
