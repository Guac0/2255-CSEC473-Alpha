result = " \
Honesty,applejack,Earth Pony,Element of Honesty,Ponyville \
Kindness,fluttershy,Pegasus,Voice of Kindness,Ponyville \
Laughter,pinkiepie,Earth Pony,Minister of Merriment,Ponyville \
Loyalty,rainbowdash,Pegasus,Loyalty incarnate,Ponyville \
Generosity,rarity,Unicorn,Lady of Generosity,Ponyville \
Magic,twilight,Alicorn,Princess of Friendship,Ponyville \
\
(6 rows affected) \
"

lines = [line.strip() for line in result.splitlines() if line.strip()]
print(lines)
# 4. Collapse into one line
# Transforms "twilight, Magic" into "twilight(Magic)"
formatted_list = []
for line in lines:
    # Split the name and virtue by the comma we set in -s
    parts = line.split(',')
    if len(parts) == 2:
        name = parts[0].strip()
        virtue = parts[1].strip()
        formatted_list.append(f"{name}({virtue})")

# Join everything with a semicolon or comma
print(formatted_list)
final_string = " | ".join(formatted_list)
print(final_string)