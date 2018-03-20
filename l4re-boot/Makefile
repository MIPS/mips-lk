DTB = $(wildcard *.dtb)

# no defaults
all:

dtb: $(DTB)

%.dtb: %.dtb.src
	dtc -O dtb -b 0 -o $@ $<

