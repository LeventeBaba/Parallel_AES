PYTHON ?= python
PDF=build/Docs.pdf
TEX=Docs.tex

all: $(PDF)

generated: scripts/generate_stats.py
	$(PYTHON) scripts/generate_stats.py

$(PDF): generated $(TEX) $(wildcard sections/*.tex)
	mkdir -p build
	lualatex -interaction=nonstopmode -halt-on-error -output-directory=build $(TEX)
	lualatex -interaction=nonstopmode -halt-on-error -output-directory=build $(TEX)

clean:
	rm -rf build generated/*.csv

.PHONY: all clean generated
