# set this to the NEXT (not yet published) version
VERSION="4.9"

function msg {
	echo ""
	echo ">>> $1"
}

if [ -z "$1" ]; then
	echo "usage: $0 [stable | dev]"
exit 1
fi

case "$1" in
"stable")
	pyfiles=$(find . -name "*.py")
	msg "Any TODOs open?"
	for f in $pyfiles; do
		grep -H "TODO" $f
	done

	msg "changing debug level to WARNING"
	sed -r -i "s/# (logger.setLevel\(logging.WARNING\))/\1/g;s/^(logger.setLevel\(logging.DEBUG\))/# \1/g" pypacker/pypacker.py

	msg "replacing version numbers"
	sed -r -i "s/version=\".+\"/version=\"$VERSION\"/g" setup.py

	msg "searching for not disabled debug output"
	grep -ir -R "^[^#]*logger.debug" *

	msg "doing style checks"
	msg "PEP8"
	pep8  --config=./qa_config.txt ./

	msg "flake8"
	flake8 --config=./qa_config.txt ./pypacker

	#msg "Pylint"
	#pylint --rcfile=./.pylintrc $pydir/*.py

	if [ "$2" = "rebuilddoc" ]; then
		msg "regenerating doc"
		export PYTHONPATH=$PYTHONPATH:$(pwd)
		rm -rf ./doc
		cd ./doc_sphinx_generated
		make clean html
		cd ..
		cp -r ./doc_sphinx_generated/_build/html/ ./doc
		git add doc
	fi

	msg "searching untracked NOT ignored files... did you forget to add anything?"
	# Show untracked files
	#git ls-files --others --exclude-from=.git/.gitignore
	# Show only ignored files
	#git ls-files --ignored  --exclude-from=.git/.gitignore
	# --exclude-standard:
	# Add the standard Git exclusions: .git/info/exclude, .gitignore in each directory, and the user’s global exclusion file.
	#git ls-files --others --exclude-standard | grep -v -P ".pyc|doc_sphinx_generated|.idea|dist"
	git ls-files --others --exclude-from=.git/.gitignore

	msg "Header definition: string instead of bytes?"
	grep -ir -Po "\"\ds\", *\".+"

	msg "set(...) instead of {...}? (still needed for list which need to be made unique)"
	grep -ir -Po " set\([^)]" | grep ".py:" | uniq
	# show set usages of form {...}
	#grep -ir -Po " {[^\:]+}" | grep ".py:" | uniq

	msg "Lower case hex numbers/upper case hex strings?"
	for f in $pyfiles; do
		# Hex numbers in uppercase
		grep -H -P "0x[0-9]{0,1}[a-f]{1,2}" $f
		# Hex bytes in lowercase
		grep -H -P "\\\\x[0-9]{0,1}[A-F]{1,2}" $f
	done

	msg "Old style unpack like unpack('H', value)? (non precompiled structs)"
	grep -ir -P "unpack\([\"\']" | grep  -P ".py:"


	if [ "$2" == "v" ]; then
		msg "re-adding tag 'v$VERSION'"
		git tag --del "v$VERSION" 1>&/dev/null
		# remove remote tag
		#git push origin :refs/tags/"v$VERSION" 1>&/dev/null
		git tag "v$VERSION"
	fi

	msg "If everything is OK call: git push -u origin master --tags; python setup.py sdist upload"
;;
"dev")
	msg "changing debug level to DEBUG"
	sed -r -i "s/# (logger.setLevel\(logging.DEBUG\))/\1/;s/^(logger.setLevel\(logging.WARNING\))/# \1/g" pypacker/pypacker.py
;;
esac
