FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Shanghai \
    PYTHONUNBUFFERED=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

RUN sed -i 's#http://http.kali.org/kali/#http://mirrors.ustc.edu.cn/kali/#' /etc/apt/sources.list.d/kali.sources && \
    printf '%s\n' \
      'Acquire::Retries "8";' \
      'Acquire::http::Timeout "30";' \
      'Acquire::https::Timeout "30";' \
      'Acquire::http::Pipeline-Depth "0";' \
      'Acquire::Queue-Mode "host";' \
      'APT::Install-Recommends "false";' \
      > /etc/apt/apt.conf.d/99secmind

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git sudo wget unzip jq yq \
      python3 python3-pip nodejs npm \
      iputils-ping ncat sshpass ripgrep fd-find

RUN apt-get install -y --no-install-recommends \
      nmap ffuf nikto naabu dirsearch \
      masscan hydra sqlmap whatweb gobuster

# Keep the larger Go based scanners in their own layer.  A transient mirror
# failure here must not invalidate the base toolchain layer above.
RUN apt-get install -y --no-install-recommends nuclei katana

RUN apt-get install -y --no-install-recommends \
      netexec gitleaks enum4linux-ng impacket-scripts \
      tcpdump tshark && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# A deliberately small, traversal-free dictionary for the controlled MCP
# directory enumeration wrappers.  The distro dictionaries include exploit
# payloads and external URLs and are not exposed to MCP callers.
RUN mkdir -p /opt/secmind
COPY common-paths.txt /opt/secmind/common-paths.txt
RUN chmod 0444 /opt/secmind/common-paths.txt

# The MCP scanner uses a reviewed local HTTP template.  It does not load
# Nuclei's broad catalogue, which can contain active payloads and remote URLs.
COPY nuclei-http-headers.yaml /opt/secmind/nuclei-http-headers.yaml
RUN chmod 0444 /opt/secmind/nuclei-http-headers.yaml

RUN npm install -g @anthropic-ai/claude-code@2.1.98 \
    @openai/codex@0.118.0 \
    @mariozechner/pi-coding-agent@0.73.0

RUN useradd -m -s /bin/bash kali && \
    printf '%s\n' 'kali ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/kali && \
    chmod 0440 /etc/sudoers.d/kali && \
    mkdir -p /home/kali/workspace/data && \
    chown -R kali:kali /home/kali/workspace

COPY --chown=kali:kali .agents /home/kali/workspace/.agents
COPY --chown=kali:kali AGENTS.md /home/kali/workspace/AGENTS.md

USER kali
WORKDIR /home/kali/workspace
