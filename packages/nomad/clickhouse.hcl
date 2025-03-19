job "clickhouse" {
  datacenters = ["${zone}"]
  type        = "service"
  node_pool   = "api"

  group "clickhouse-server-1" {
    count = 1

    network {
      port "http" {
        to = 8123
        static = 8123
      }
      port "tcp" {
        to = 9000
        static = 9000

      }
      port "interserver" {
        to = 9009
      }
    }

    service {
      name = "clickhouse"
      port = "tcp"

      check {
        type     = "tcp"
        port     = "tcp"
        interval = "10s"
        timeout  = "5s"
      }

      tags = [
        "traefik.enable=true",
        "traefik.http.routers.clickhouse.rule=Host(`clickhouse.service.consul`)",
      ]
    }


    task "server" {
      driver = "docker"

      kill_timeout = "120s"

      env {
        CLICKHOUSE_USERNAME           = "${clickhouse_username}"
        CLICKHOUSE_PASSWORD           = "${clickhouse_password}"
      }

      config {
        image = "clickhouse/clickhouse-server:25.2.2.39"
        ports = ["http", "tcp", "interserver"]
        
        ulimit {
          nofile = "262144:262144"
        }

        volumes = [
          "local/server_config.xml:/etc/clickhouse-server/config.d/server_config.xml",
          "local/macros.xml:/etc/clickhouse-server/config.d/macros.xml",
          "local/storage_config.xml:/etc/clickhouse-server/config.d/storage.xml",
          "local/users.xml:/etc/clickhouse-server/users.d/users.xml",
          # "/var/lib/clickhouse:/var/lib/clickhouse"
        ]
      }

      template {
        data = <<EOH
<clickhouse>
    
    <logger>
        <console>1</console>
    </logger>
    <zookeeper>
        <node>
            <host>{{ range service "clickhouse-keeper" }}{{ .Address }}{{ end }}</host>
            <port>{{ range service "clickhouse-keeper" }}{{ .Port }}{{ end }}</port>
        </node>
    </zookeeper>

    <remote_servers>
        <my_cluster>
            <shard>
                <replica>
                    <host>{{ env "NOMAD_IP_http" }}</host>
                    <port>9000</port>
                </replica>
            </shard>
            <shard>
                <replica>
                    <host>{{ range service "clickhouse-server-2" }}{{ .Address }}{{ end }}</host>
                    <port>9000</port>
                </replica>
            </shard>
        </my_cluster>
    </remote_servers>

    <listen_host>0.0.0.0</listen_host>
    <interserver_http_host>{{ env "NOMAD_IP_interserver" }}</interserver_http_host>
    
    # Enable waiting for shutdown
    <shutdown_wait_unfinished>60</shutdown_wait_unfinished>
    <shutdown_wait_unfinished_queries>1</shutdown_wait_unfinished_queries>
</clickhouse>
EOH
        destination = "local/server_config.xml"
      }

      template {
        data = <<EOH
<clickhouse>
    <storage_configuration>
        <disks>
          <disk_name_1>
            <path>/var/clickhouse/</path>
        </disk_name_1>
        </disks>
        <policies>
            <disk_name_1>
                <volumes>
                    <main>
                        <disk>disk_name_1</disk>
                    </main>
                </volumes>
            </disk_name_1>
        </policies>
    </storage_configuration>
    <merge_tree>
        <storage_policy>disk_name_1</storage_policy>
    </merge_tree>
</clickhouse>
EOH
        destination = "local/storage_config.xml"
      }

      template {
        data = <<EOH
<clickhouse>
    <macros>
        <cluster>my_cluster</cluster>
        <shard>01</shard>
        <replica>01</replica>
    </macros>
</clickhouse>
EOH
        destination = "local/macros.xml"
      }

      template {
        data = <<EOH
<?xml version="1.0"?>
<clickhouse>
    <users>
        <${username}>
            <password_sha256_hex>${password_sha256_hex}</password_sha256_hex>
            <networks>
                <ip>::/0</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
            <access_management>1</access_management>
        </${username}>
    </users>
</clickhouse>
EOH
        destination = "local/users.xml"
      }

      resources {
        cpu    = 1000
        memory = 2048
      }

      service {
        name = "clickhouse"
        port = "http"
        
        check {
          type     = "http"
          path     = "/ping"
          interval = "10s"
          timeout  = "2s"
        }

        tags = [
          "traefik.enable=true",
          "traefik.http.routers.clickhouse.rule=Host(`clickhouse.service.consul`)",
        ]
      }
    }
  }
}
