#!/bin/bash

pushd $(dirname "$0")
docker run --rm -v $PWD:/home/marp/app/ -e LANG=$LANG marpteam/marp-cli --html docs/slides.md --pdf -o target/slides.pdf
docker run --rm -v $PWD:/home/marp/app/ -e LANG=$LANG marpteam/marp-cli --html docs/slides.md --pptx -o target/slides.pptx
docker run --rm -v $PWD:/home/marp/app/ -e LANG=$LANG marpteam/marp-cli --html docs/slides.md --html -o target/slides.html
popd