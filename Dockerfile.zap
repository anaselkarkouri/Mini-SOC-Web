FROM ghcr.io/zaproxy/zaproxy:bare
RUN zap.sh -cmd -addoninstall automation -addoninstall ascanrules -addoninstall pscanrules -addoninstall reports
