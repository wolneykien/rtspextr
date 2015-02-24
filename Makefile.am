
bin_PROGRAMS = rtspextr

if PCAP
rtspextr_LDADD = -lpcap
endif

man1_MANS = rtspextr.1

%.1: %.md
	ronn --roff $< --pipe >$@

bin_SCRIPTS = sppspatch
