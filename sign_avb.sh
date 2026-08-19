#part_name signed_img img_to_sign [size_mb]
PROP_FILE=$(mktemp)
INFO_OUTPUT=$(./avbctl info_image --image $2)
PARTITION_SIZE=$(echo "$INFO_OUTPUT" | grep -E "^Image size:" | awk '{print $(NF-1)}')
echo "$INFO_OUTPUT" | grep "Prop:" > "$PROP_FILE"

CMD="./avbctl add_hash_footer --image $3 --partition_name $1 --key rsa4096_$1.pem --algorithm SHA256_RSA4096"

if [ -z "$PARTITION_SIZE" ] && [ -n "$4" ]; then
    PARTITION_SIZE=$(($4 * 1024 * 1024))
elif [ -z "$PARTITION_SIZE" ]; then
    echo "Error: Failed to extract partition size from image, and no size_mb provided." >&2
    exit 1
fi

if [ -n "$PARTITION_SIZE" ]; then
    CMD="$CMD --partition_size $PARTITION_SIZE"
fi
 
while IFS= read -r line; do
    PROP_KEY=$(echo "$line" | sed -E "s/^\s*Prop:\s*([^ ]+).*$/\1/")
    PROP_VALUE=$(echo "$line" | sed -E "s/^\s*Prop:.*->\s*'([^ ]+)'.*$/\1/")
    CMD="$CMD --prop $PROP_KEY:$PROP_VALUE"
done < "$PROP_FILE"
rm "$PROP_FILE"
echo "$INFO_OUTPUT"
echo "$CMD"
$CMD
