ENV := $(shell cat ../../.last_used_env || echo "not-set")
-include ../../.env.${ENV}

.PHONY: build
build:
	./build.sh

.PHONY: upload
upload:
	./upload.sh $(GCP_PROJECT_ID)

.PHONY: build-and-upload
build-and-upload: build upload

.PHONY: download
download:
	@echo "Downloading jailer versions from bucket..."
	@mkdir -p /tmp/jailer-versions
	@gsutil -m cp -r "gs://$(GCP_PROJECT_ID)-jailer-versions/*" /tmp/jailer-versions/
	@ls -la /tmp/jailer-versions/

.PHONY: clean
clean:
	rm -rf builds