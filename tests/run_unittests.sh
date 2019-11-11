# Downloads KUnit and builds the test kernel
MSG_OK='OK'
MSG_FAIL='FAIL'

PKG_OK=$(dpkg-query -W --showformat='${Status}\n' build-essential|grep "install ok installed")
printf "Checking for build-essential: " 
if [ "" == "$PKG_OK" ]; then
	echo $MSG_FAIL
	echo "No build-essential. Please install with 'apt install build-essential' or your system's equivalent"
	#apt install --force-yes --yes build-essential
	exit
else
	echo $MSG_OK
fi

PKG_OK=$(dpkg-query -W --showformat='${Status}\n' bison|grep "install ok installed")
printf "Checking for bison: "
if [ "" == "$PKG_OK" ]; then
	echo $MSG_FAIL
	echo "No bison. Please install with 'apt install bison' or your system's equivalent"
	exit
else
	echo $MSG_OK
fi

PKG_OK=$(dpkg-query -W --showformat='${Status}\n' flex|grep "install ok installed")
printf "Checking for flex: "
if [ "" == "$PKG_OK" ]; then
	echo $MSG_FAIL
	echo "No flex. Please install with 'apt install flex' or your system's equivalent"
	exit
else
	echo $MSG_OK
fi

PKG_OK=$(dpkg-query -W --showformat='${Status}\n' bc|grep "install ok installed")
printf "Checking for bc: "
if [ "" == "$PKG_OK" ]; then
	echo $MSG_FAIL
	echo "No bc. Please install with 'apt install bc' or your system's equivalent"
	exit
else
	echo $MSG_OK
fi



# download kunit stable
printf "Checking for kunit: "
if [ ! -d "./kunit" ]; then
	echo "Cloning..."
	git clone -b kunit/alpha/master https://kunit.googlesource.com/linux kunit
else
	echo $MSG_OK
fi


# enter new directory
cd kunit

# symlink kunitconfig into the kernel
printf "Checking for kunitconfig symlink: "
if [ ! -L "kunitconfig" ]; then
	echo "Adding..."
	ln -s ../kunitconfig/kunitconfig kunitconfig
else
	echo $MSG_OK
fi

# setup Drawbridge config
printf "Checking for drawbridge testfiles: "
if [ ! -d "./drawbridge" ]; then
	echo "Creating..."
	mkdir drawbridge
	cp ../../kernel/*.c drawbridge/
	cp ../../kernel/*.h drawbridge/
	cp ../unittests/* drawbridge/
	echo 'source "drawbridge/Kconfig"' >> Kconfig
else
	echo $MSG_OK
fi

# setup config
make mrproper

# build and start the tests 
./tools/testing/kunit/kunit.py run 2>/dev/null

