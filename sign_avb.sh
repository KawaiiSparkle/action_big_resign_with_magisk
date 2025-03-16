#part_name signed_img img_to_sign
PROP_FILE=$(mktemp)
INFO_OUTPUT=$(python avbtool info_image --image $2)
PARTITION_SIZE=$(echo "$INFO_OUTPUT" | grep -E "^Image size:" | awk '{print $(NF-1)}')
echo "$INFO_OUTPUT" | grep "Prop:" > "$PROP_FILE"
CMD="python avbtool add_hash_footer --image $3 --partition_name $1 --partition_size $PARTITION_SIZE --key rsa4096_$1.pem --algorithm SHA256_RSA4096"

while IFS= read -r line; do
    PROP_KEY=$(echo "$line" | sed -E "s/^\s*Prop:\s*([^ ]+).*$/\1/")
    PROP_VALUE=$(echo "$line" | sed -E "s/^\s*Prop:.*->\s*'([^ ]+)'.*$/\1/")
    CMD="$CMD --prop $PROP_KEY:$PROP_VALUE"
done < "$PROP_FILE"
rm "$PROP_FILE"
$CMD
