package registry

import (
	"regexp"
	"strconv"
	"strings"
)

// A tag reads as a version when it is an optional word prefix ("v",
// "version-", "jammy-"), dotted numbers, and an optional suffix after a
// separator ("-alpine", "-ls245"). Without the separator, "sha-1a2b3c" would
// read as version 1.
var (
	tagRe    = regexp.MustCompile(`^([^0-9]*?)([0-9]+(?:\.[0-9]+)*)([-_.+].*)?$`)
	prefixRe = regexp.MustCompile(`^(?:[A-Za-z]+[-_])*[vV]?$`)
	digitsRe = regexp.MustCompile(`[0-9]+`)
)

// version is a tag taken apart. Two tags are comparable when their shapes are
// equal: the same prefix, as many numbers, and the same suffix once its
// digits are blanked out. So 1.27.3 compares with 1.29.0 but not with 1.29 or
// 1.29.0-rc1, and 1.27.3-alpine3.20 compares with 1.27.5-alpine3.21.
type version struct {
	shape string
	nums  []uint64 // the version numbers, then the suffix's numbers
	major uint64
}

func parseTag(tag string) (version, bool) {
	m := tagRe.FindStringSubmatch(tag)
	if m == nil || !prefixRe.MatchString(m[1]) {
		return version{}, false
	}
	var nums []uint64
	main := strings.Split(m[2], ".")
	for _, part := range append(main, digitsRe.FindAllString(m[3], -1)...) {
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return version{}, false
		}
		nums = append(nums, n)
	}
	shape := m[1] + "|" + strconv.Itoa(len(main)) + "|" + digitsRe.ReplaceAllString(m[3], "#")
	return version{shape: shape, nums: nums, major: nums[0]}, true
}

func (v version) less(o version) bool {
	for i := range v.nums {
		if v.nums[i] != o.nums[i] {
			return v.nums[i] < o.nums[i]
		}
	}
	return false
}

// Versioned reports whether tag reads as a version; floating tags such as
// latest or stable only get the digest check.
func Versioned(tag string) bool {
	_, ok := parseTag(tag)
	return ok
}

// Newer picks, from a repository's tags, the newest tag of the same shape as
// current and the newest one in current's major version. Each is "" unless
// it is newer than current.
func Newer(current string, tags []string) (newest, newestInMajor string) {
	cur, ok := parseTag(current)
	if !ok {
		return "", ""
	}
	best, bestMajor := cur, cur
	for _, t := range tags {
		v, ok := parseTag(t)
		if !ok || v.shape != cur.shape || !cur.less(v) {
			continue
		}
		if best.less(v) {
			best, newest = v, t
		}
		if v.major == cur.major && bestMajor.less(v) {
			bestMajor, newestInMajor = v, t
		}
	}
	return newest, newestInMajor
}
