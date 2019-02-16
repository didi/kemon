XCODE_PROJECT = kemon.xcodeproj
CC = /usr/bin/xcodebuild

build:
	$(CC) build -project $(XCODE_PROJECT) -configuration Debug
	$(CC) build -project $(XCODE_PROJECT) -configuration Release

clean:
	$(CC) clean -project $(XCODE_PROJECT) -configuration Debug
	$(CC) clean -project $(XCODE_PROJECT) -configuration Release