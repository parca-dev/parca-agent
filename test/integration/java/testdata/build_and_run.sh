#!/bin/sh

javac $1.java
exec java -XX:+PreserveFramePointer -XX:-Inline $1
