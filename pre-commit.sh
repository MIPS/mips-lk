#!/bin/sh
# pre-commit script that runs checkpatch.pl for code-style errors
# please, link the .git/hooks/pre-commit to this script using:
#	ln -s ../../pre-commit.sh .git/hooks/pre-commit

# ignore some types of messages
IGNORELIST="CONST_STRUCT,NEW_TYPEDEFS,FILE_PATH_CHANGES"
CHECKPATCH="./checkpatch.pl"
CHECKPATCH_COMMAND="$CHECKPATCH --no-tree --ignore $IGNORELIST"

echo "Running the pre-commit checkpatch.pl script..."
git diff --cached -- . ':(exclude)external' ':(exclude)l4re-boot' | $CHECKPATCH_COMMAND
RESULT=$?

[ $RESULT -ne 0 ] && exit 1
exit 0
