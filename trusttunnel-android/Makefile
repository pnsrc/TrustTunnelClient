.PHONY: clean build release debug install help

help:
	@echo "TrustTunnel Android Build Targets:"
	@echo "  make debug       - Build debug APK"
	@echo "  make release     - Build release APK"
	@echo "  make install     - Install debug APK on device"
	@echo "  make bundle      - Build release AAB for Play Store"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make test        - Run unit tests"

debug:
	@echo "Building debug APK..."
	./gradlew assembleDebug

release:
	@echo "Building release APK..."
	./gradlew assembleRelease

bundle:
	@echo "Building release AAB..."
	./gradlew bundleRelease

install: debug
	@echo "Installing debug APK..."
	adb install -r app/build/outputs/apk/debug/app-debug.apk

test:
	@echo "Running unit tests..."
	./gradlew test

clean:
	@echo "Cleaning build artifacts..."
	./gradlew clean
	rm -rf build/

lint:
	@echo "Running lint checks..."
	./gradlew lint

dependencies:
	@echo "Displaying dependency tree..."
	./gradlew dependencies
