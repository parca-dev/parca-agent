#!/bin/sh

javac Main.java
exec java  -XX:+PreserveFramePointer Main