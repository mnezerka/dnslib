set -o errexit
set -o pipefail
set -o nounset

mkdir build
cd build

cmake ../src
make
./unittests
