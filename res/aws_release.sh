#!/bin/sh

# go to root
cd `dirname $0`
cd ..

if [ "$1" != "prod" ] && [ "$1" != "test" ] ; then
    echo 'Usage: ./res/aws_release prod|test'
    exit 0
fi

# switch branch
git checkout master
git branch -D release/$1
git checkout -b release/$1
git merge master --no-edit

# abort if tests fail
set -e

# build and test
rm -rf node_modules
npm install
npm test

# install only production dependencies
rm -rf node_modules/
npm install --production

# delete .gitignore files before adding to git for aws deployment
find node_modules/ -name ".gitignore" -exec rm -rf {} \;

# Add runtime dependencies to git
sed -i "" '/node_modules/d' .gitignore
git add .gitignore node_modules/
git commit -m "Update release"

# push to aws
eb deploy keyserver-$1

# switch back to master branch
git checkout master