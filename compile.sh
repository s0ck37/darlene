out_dir=build
src_dir=src
bin_name=darlene.bin
version="v1.1"

echo "Creating $out_dir directory"
mkdir -p $out_dir
echo "Compiling darlene"
gcc $src_dir/main.c $src_dir/sha256.c $src_dir/sha256.h $src_dir/aes.c $src_dir/aes.h -o $out_dir/$bin_name -DVERSION="\"$version\""
echo "Binary file saved to $out_dir/$bin_name"
