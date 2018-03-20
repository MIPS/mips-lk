#!/bin/bash

set -e

MIPSSIM_APPLICATION=$1

# set the IASim platform configuration file to use
MIPSSIM_CFG_FILE=$PWD/mipssim-p5600.cfg

export MIPSSIM_APPLICATION=${MIPSSIM_APPLICATION}
case ${MIPSSIM_APPLICATION} in
	/*) ;;
	*) export MIPSSIM_APPLICATION=$PWD/${MIPSSIM_APPLICATION};;
esac

# source IASim setup script if not already done
# please refer to the IASim Getting Started Guide
if [ "X${IASIM}" == "X" ]; then
	# set the path to the IASim installation and version
	if [ "X${IASIM_INSTALL_PATH}" == "X" ]; then
		IASIM_INSTALL_PATH=/path_to_install_dir/iasim-3.7/IASim_3_7_2
	fi

	# locate the FLEXlm license key
	if [ "X${IMGTEC_LICENSE_FILE}" == "X" ]; then
		export IMGTEC_LICENSE_FILE=MyLicense.lic
	fi

	# source IASim setup script: requires MIPS_HOME and IASIM
	export MIPS_HOME=$(dirname ${IASIM_INSTALL_PATH})
	export IASIM=$(basename ${IASIM_INSTALL_PATH})
	echo "IASIM_INSTALL_PATH=${IASIM_INSTALL_PATH}"
	echo "MIPS_HOME=${MIPS_HOME}"
	echo "IASIM=${IASIM}"

	echo
	echo "source ${MIPS_HOME}/${IASIM}/setup/setup.sh"
	source ${MIPS_HOME}/${IASIM}/setup/setup.sh
	env | grep IMPERAS
	echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"
fi

# The SIMULATOR_PORT environment variable can optionally be set to wait for a
# telnet localhost <port_num> connection instead of automatically opening a
# terminal console
#export SIMULATOR_PORT=11111
cd ${MIPS_HOME}/${IASIM}/mips-img-malta/luaMalta
exec ./mips-img-malta.Linux64.exe ${MIPSSIM_CFG_FILE}
