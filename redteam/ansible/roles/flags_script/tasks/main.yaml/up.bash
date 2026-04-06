duration=$((10 * 60))
interval=9
end=$((SECONDS + duration))
while [ $SECONDS -lt $end ]; do
  echo "andrew niebur" >> /flags/flag.txt
  sleep $interval
done