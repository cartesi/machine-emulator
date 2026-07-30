#!/bin/bash
set -e

IFS=$'\n'
rawPackages=( $(dpkg-query --show --showformat='${db:Status-Abbrev} ${source:Package}=${source:Version} ${binary:Package}=${Version}\n' 2>/dev/null) )
unset IFS

declare -A packages=()
for rawPackage in "${rawPackages[@]}"; do
	rawPackage=( $rawPackage )
	stat="${rawPackage[0]}"
	case "$stat" in
		i?|h?)
			# "install" or "hold"
			;;
		*)
			# skip "unknown", "remove", "purge"
			continue
			;;
	esac
	src="${rawPackage[1]}"
	bin="${rawPackage[2]}"
	[ -z "${packages[$src]}" ] || packages[$src]+=' '
	packages[$src]+="$bin"
done

if [ "${#packages[@]}" -eq 0 ]; then
	# not Debian-based
	exit 1
fi

if [ -z "${DPKG_ARCH:-}" ]; then
	echo >&2 "error: DPKG_ARCH is not set"
	exit 1
fi
apt_arch_opt=(-o "APT::Architecture=$DPKG_ARCH" -o "APT::Architectures=$DPKG_ARCH")

# resolve package lists against a fixed archive snapshot so the
# output does not drift as the live archive moves on
apt_snapshot_opt=()
if [ -n "${APT_SNAPSHOT:-}" ]; then
	apt_snapshot_opt=(--snapshot="$APT_SNAPSHOT")
fi

if [ -e /etc/apt/sources.list ] || [ -d /etc/apt/sources.list.d ]; then
	# make sure we have "deb-src" entries for "apt-get source"
	# (deb822 files must not have their lines duplicated; a stanza with
	# two Types fields makes "apt-get update --snapshot" abort)
	find /etc/apt/sources.list* \
		-type f -name '*.sources' \
		-exec sed -i 's/^Types: deb$/Types: deb deb-src/' '{}' +
	if [ "${#apt_snapshot_opt[@]}" -gt 0 ]; then
		# Require --snapshot for these sources instead of falling back to the live archive.
		find /etc/apt/sources.list* \
			-type f -name '*.sources' \
			-exec sed -i -e '/^Snapshot:/d' -e '/^Types:/a Snapshot: enable' '{}' +
	fi
	find /etc/apt/sources.list* \
		-type f ! -name '*.sources' \
		-exec sed -i 'p; s/^deb /deb-src /' '{}' +

	# retry a few times if "apt-get update" fails
	tries=5
	while ! apt-get "${apt_arch_opt[@]}" update -qq; do
		(( --tries )) || :
		if [ "$tries" -le 0 ]; then
			echo >&2 'error: failed to "apt-get update" after multiple attempts'
			exit 1
		fi
	done

	# switch the package lists to the pinned snapshot; this must come
	# after a regular update, or apt aborts on deb822 sources that have
	# multiple suites (assertion failure in debmetaindex.cc)
	if [ "${#apt_snapshot_opt[@]}" -gt 0 ]; then
		apt-get "${apt_arch_opt[@]}" "${apt_snapshot_opt[@]}" update -qq
	fi
fi

IFS=$'\n'
sortedSources=( $(echo "${!packages[*]}" | sort) )
unset IFS

echo
echo '## `dpkg` (`.deb`-based packages)'

# prints "$2$1$3$1...$N"
join() {
	local sep="$1"; shift
	local out; printf -v out "${sep//%/%%}%s" "$@"
	echo "${out#$sep}"
}

for src in "${sortedSources[@]}"; do
	echo
	echo '### `dpkg` source package: `'"$src"'`'
	echo
	echo 'Binary Packages:'
	echo
	for bin in ${packages[$src]}; do
		echo '- `'"$bin"'`'
	done

	# parse /usr/share/doc/BIN/copyright
	licenses=()
	licenseFiles=()
	for bin in ${packages[$src]}; do
		# https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
		# http://dep.debian.net/deps/dep5/
		binPkg="${bin%%=*}"
		binPkgOnly="${binPkg%%:*}"
		f=
		for try in \
			"/usr/share/doc/$bin/copyright" \
			"/usr/share/doc/$binPkg/copyright" \
			"/usr/share/doc/$binPkgOnly/copyright" \
		; do
			if [ -f "$try" ]; then
				f="$try"
				break
			fi
		done
		if [ -z "$f" ]; then
			echo >&2
			echo >&2 "**WARNING:** '/usr/share/doc/$binPkgOnly/copyright' is missing!"
			echo >&2
			continue
		fi
		IFS=$'\n'
		licenses+=( $(gawk -F ':[ \t]+' '$1 == "License" && NF > 1 { gsub(/^License:[ \t]+/, ""); print }' "$f") )
		licenses+=( $(grep -oE '/usr/share/common-licenses/[0-9a-zA-Z_.+-]+' "$f" | cut -d/ -f5-) )
		unset IFS
		licenseFiles+=( "$f" )
	done
	if [ "${#licenses[@]}" -gt 0 ]; then
		IFS=$'\n'
		licenses=( $(
			echo "${licenses[*]}" \
				| sed -r \
					-e 's/ (and|or) /\n/g' \
					-e 's/[.,]+$//' \
				| sort -u
		) )
		unset IFS

		echo
		echo 'Licenses: (parsed from: `'"$(join '`, `' "${licenseFiles[@]}")"'`)'
		echo
		for lic in "${licenses[@]}"; do
			echo '- `'"$lic"'`'
		done
	else
		echo
		echo '**WARNING:** unable to detect licenses! (package likely not compliant with DEP-5)  '
		echo 'If source is available (seen below), check the contents of `debian/copyright` within it.'
		echo
	fi

	sourcesUrl="https://sources.debian.net/src/${src//=//}/"
	snapshotUrl="http://snapshot.debian.org/package/${src//=//}/"

	# A binary that came from a repository must have a resolvable source. A
	# binary installed from a local .deb (e.g. machine-guest-tools) has no
	# archive source, so a missing source is expected only in that case. Tell
	# the two apart by asking apt whether any of this source's binaries is
	# available from a repository at all.
	fromRepo=
	for bin in ${packages[$src]}; do
		binPkg="${bin%%=*}"
		binPkgOnly="${binPkg%%:*}"
		if [ -n "$(apt-cache "${apt_arch_opt[@]}" madison "$binPkgOnly" 2>/dev/null)" ]; then
			fromRepo=1
			break
		fi
	done

	aptSourceArgs=( apt-get "${apt_arch_opt[@]}" "${apt_snapshot_opt[@]}" source -qq --print-uris "$src" )
	aptSource=
	if [ -n "$fromRepo" ]; then
		# Repository package: the source must resolve. Retry to ride out
		# transient archive hiccups, then fail hard rather than emit a report
		# that silently differs from the committed one. A persistent failure
		# means the pinned snapshot's source index has not converged for this
		# version; move the snapshot pin back to a converged date.
		tries=5
		while ! aptSource="$("${aptSourceArgs[@]}" 2>/dev/null)" || [ -z "$aptSource" ]; do
			(( --tries )) || :
			if [ "$tries" -le 0 ]; then
				echo >&2 "error: no source for repository package '$src' (snapshot index not converged or archive unreachable)"
				exit 1
			fi
		done
	fi

	# Normalize the captured source URIs so the report stays byte-stable.
	# apt prints whichever location currently serves each file. While a
	# version is still in the pool that is the live mirror with a SHA256
	# digest, and once it has been superseded it is the pinned snapshot
	# host with a SHA512 digest. Neither the host nor the digest is needed
	# to satisfy the source-distribution obligation, and the two digests
	# cannot be reconciled because they use different algorithms. Rewrite
	# every URL to the durable snapshot host and drop the digest field so
	# the output changes only when the committed rootfs or the snapshot pin
	# does. apt also emits the files (.dsc, .orig.tar, .debian.tar) of a
	# source package in no particular order, so sort the lines as well.
	if [ -n "$aptSource" ]; then
		sedArgs=( -E -e 's/ [A-Za-z0-9]+:[0-9a-fA-F]+$//' )
		if [ -n "${APT_SNAPSHOT:-}" ]; then
			sedArgs+=( -e "s#'[^']*/pool/#'https://snapshot.ubuntu.com/ubuntu/${APT_SNAPSHOT}/pool/#" )
		fi
		aptSource="$(printf '%s\n' "$aptSource" | sed "${sedArgs[@]}" | sort)"
	fi

	if [ -n "$aptSource" ]; then
		echo
		echo 'Source:'
		echo
		echo '```console'
		echo '$' "${aptSourceArgs[@]}"
		echo "$aptSource"
		echo '```'
		case "$aptSource" in
			*.debian.org/*)
				# _probably_ Debian -- let's link to sources.debian.net too
				echo
				echo 'Other potentially useful URLs:'
				echo
				echo '- '"$sourcesUrl"' (for browsing the source)'
				echo '- '"$sourcesUrl"'debian/copyright/ (for direct copyright/license information)'
				echo '- '"$snapshotUrl"' (for access to the source package after it no longer exists in the archive)'
				;;
		esac
	else
		echo
		echo '**WARNING:** no archive source (package was installed from a local `.deb`, not a repository).'
		echo
	fi
done
