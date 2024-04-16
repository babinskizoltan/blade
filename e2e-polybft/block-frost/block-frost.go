package blockfrost

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xPolygon/polygon-edge/e2e-polybft/cardanofw"
	"github.com/0xPolygon/polygon-edge/helper/common"
)

type BlockFrost struct {
	Id          int
	RootDir     string
	ClusterName string
}

type PostgresConfig struct {
	User     string
	Password string
	Db       string
}

func NewBlockFrost(cluster *cardanofw.TestCardanoCluster, id int) (*BlockFrost, error) {
	clusterName := fmt.Sprintf("cluster-%d-%d", id, time.Now().Unix())
	dockerDir := path.Join("../../e2e-docker-tmp", clusterName)
	if err := common.CreateDirSafe(dockerDir, 0750); err != nil {
		return nil, err
	}

	err := resolvePostgresFiles(dockerDir)
	if err != nil {
		return nil, err
	}

	err = resolveGenesisFiles(cluster.Config.TmpDir, dockerDir)
	if err != nil {
		return nil, err
	}

	err = resolveConfigFiles(cluster.Config.TmpDir, dockerDir)
	if err != nil {
		return nil, err
	}

	postgresPort := 5432 + id
	blockfrostPort := 12000 + id
	err = resolveDockerCompose(dockerDir, postgresPort, blockfrostPort)
	if err != nil {
		return nil, err
	}

	return &BlockFrost{
		Id:          id,
		RootDir:     dockerDir,
		ClusterName: clusterName,
	}, nil
}

func (bf *BlockFrost) Start() error {
	dockerFile := filepath.Join(bf.RootDir, "docker-compose.yml")

	_, err := runCommand("docker-compose", []string{"-f", dockerFile, "up", "-d"})
	if err != nil {
		return err
	}

	return nil
}

func (bf *BlockFrost) Stop() error {
	dockerFile := filepath.Join(bf.RootDir, "docker-compose.yml")

	_, err := runCommand("docker-compose", []string{"-f", dockerFile, "down"})
	if err != nil {
		return err
	}

	// remove volumes
	runCommand("docker", []string{"volume", "rm",
		fmt.Sprintf(bf.ClusterName, "-db-sync-data"),
		fmt.Sprintf(bf.ClusterName, "-node-db"),
		fmt.Sprintf(bf.ClusterName, "-node-ipc"),
		fmt.Sprintf(bf.ClusterName, "-postgres")})

	return nil
}

func resolvePostgresFiles(dockerDir string) error {
	secretsPath := path.Join(dockerDir, "secrets")
	if err := common.CreateDirSafe(secretsPath, 0750); err != nil {
		return err
	}

	postgresConfig := getPostgresConfig()

	dbFile := filepath.Join(secretsPath, "postgres_db")
	if err := os.WriteFile(dbFile, []byte(postgresConfig.Db), 0644); err != nil {
		return err
	}

	pwFile := filepath.Join(secretsPath, "postgres_password")
	if err := os.WriteFile(pwFile, []byte(postgresConfig.Password), 0644); err != nil {
		return err
	}

	userFile := filepath.Join(secretsPath, "postgres_user")
	if err := os.WriteFile(userFile, []byte(postgresConfig.User), 0644); err != nil {
		return err
	}

	return nil
}

func resolveGenesisFiles(rootDir string, dockerDir string) error {
	nodeGenesis := path.Join(rootDir, "genesis")

	dockerGenesis := path.Join(dockerDir, "genesis")
	if err := common.CreateDirSafe(dockerGenesis, 0750); err != nil {
		return err
	}

	copyDirectory(nodeGenesis, dockerGenesis)

	return nil
}

func resolveConfigFiles(rootDir string, dockerDir string) error {
	configPath := path.Join(dockerDir, "config")
	if err := common.CreateDirSafe(configPath, 0750); err != nil {
		return err
	}

	// Blockfrost config (empty)
	blockfrostPath := path.Join(configPath, "blockfrost")
	if err := common.CreateDirSafe(blockfrostPath, 0750); err != nil {
		return err
	}

	// DBSync config
	dbsyncPath := path.Join(configPath, "dbsync")
	if err := common.CreateDirSafe(dbsyncPath, 0750); err != nil {
		return err
	}

	dbsyncConfigSrc := "../block-frost/docker-files/dbsync_config.json"
	dbsyncConfig := filepath.Join(dbsyncPath, "config.json")
	copyFile(dbsyncConfigSrc, dbsyncConfig)

	nodeConfigSrc := "../block-frost/docker-files/node_config.yaml"
	nodeConfig := filepath.Join(dbsyncPath, "config.yaml")
	copyFile(nodeConfigSrc, nodeConfig)

	byronGenesis := filepath.Join(rootDir, "genesis/byron/genesis.json")
	byronHash, err := runCommand("cardano-cli", []string{"byron", "genesis", "print-genesis-hash", "--genesis-json", byronGenesis})
	if err != nil {
		return err
	}
	appendToFile(nodeConfig, fmt.Sprintf("ByronGenesisHash: %s", byronHash))

	shelleyGenesis := filepath.Join(rootDir, "genesis/shelley/genesis.json")
	shelleyHash, err := runCommand("cardano-cli", []string{"shelley", "genesis", "hash", "--genesis", shelleyGenesis})
	if err != nil {
		return err
	}
	appendToFile(nodeConfig, fmt.Sprintf("ShelleyGenesisHash: %s", shelleyHash))

	alonzoGenesis := filepath.Join(rootDir, "genesis/shelley/genesis.alonzo.json")
	alonzoHash, err := runCommand("cardano-cli", []string{"alonzo", "genesis", "hash", "--genesis", alonzoGenesis})
	if err != nil {
		return err
	}
	appendToFile(nodeConfig, fmt.Sprintf("AlonzoGenesisHash: %s", alonzoHash))

	conwayGenesis := filepath.Join(rootDir, "genesis/shelley/genesis.conway.json")
	conwayHash, err := runCommand("cardano-cli", []string{"conway", "genesis", "hash", "--genesis", conwayGenesis})
	if err != nil {
		return err
	}
	appendToFile(nodeConfig, fmt.Sprintf("ConwayGenesisHash: %s", conwayHash))

	// Relay node config
	relayPath := path.Join(configPath, "relay")
	if err := common.CreateDirSafe(relayPath, 0750); err != nil {
		return err
	}

	nodeConfig = filepath.Join(relayPath, "configuration.yaml")
	copyFile(nodeConfigSrc, nodeConfig)

	// Read first node port from second node's topology file
	node2topology := filepath.Join(rootDir, "node-spo2/topology.json")
	topology, err := getTopology(node2topology)
	if err != nil {
		return err
	}
	topologyFile := filepath.Join(relayPath, "topology.json")
	if err := os.WriteFile(topologyFile, []byte(topology), 0644); err != nil {
		return err
	}

	return nil
}

func resolveDockerCompose(dockerDir string, postgresPort int, blockfrostPort int) error {
	dockerFileSrc := "../block-frost/docker-files/docker-compose.yml"
	dockerFile := filepath.Join(dockerDir, "docker-compose.yml")
	copyFile(dockerFileSrc, dockerFile)

	replaceLine(dockerFile, "      - ${POSTGRES_PORT:-5432}:5432", fmt.Sprintf("      - ${POSTGRES_PORT:-%d}:%d", postgresPort, postgresPort))
	replaceLine(dockerFile, "      - POSTGRES_PORT=5432", fmt.Sprintf("      - POSTGRES_PORT=%d", postgresPort))

	replaceLine(dockerFile, "      - ${POSTGRES_PORT:-3000}:3000", fmt.Sprintf("      - ${POSTGRES_PORT:-%d}:%d", blockfrostPort, blockfrostPort))
	replaceLine(dockerFile, "      - BLOCKFROST_CONFIG_SERVER_PORT=3000", fmt.Sprintf("      - BLOCKFROST_CONFIG_SERVER_PORT=%d", blockfrostPort))

	return nil
}

func getTopology(topologyFile string) (string, error) {
	port, err := getFirstPortFromTopologyFile(topologyFile)
	if err != nil {
		return "", err
	}

	topologyBase := `
{
	"Producers": [
		{
			"addr": "127.0.0.1",
			"port": %s,
			"valency": 1
		}
	]
}`

	topology := fmt.Sprintf(topologyBase, port)
	return topology, nil
}

func getPostgresConfig() *PostgresConfig {
	user := os.Getenv("POSTGRES_USER")
	if user == "" {
		// fallback
		user = "postgres"
	}

	password := os.Getenv("POSTGRES_PASSWORD")
	if password == "" {
		// fallback
		password = "password"
	}

	dbName := os.Getenv("POSTGRES_DB")
	if dbName == "" {
		// fallback
		dbName = "testdb"
	}

	return &PostgresConfig{
		User:     user,
		Password: password,
		Db:       dbName,
	}
}

func getFirstPortFromTopologyFile(topologyFile string) (string, error) {
	file, err := os.Open(topologyFile)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return "", nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, `"port"`) {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				port := strings.TrimSpace(strings.Trim(parts[1], ","))
				return port, nil
			}
		}
	}

	err = scanner.Err()
	return "", err
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	return nil
}

func copyDirectory(srcDir, dstDir string) error {
	files, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		srcFile := filepath.Join(srcDir, file.Name())
		dstFile := filepath.Join(dstDir, file.Name())

		if file.IsDir() {
			err = os.MkdirAll(dstFile, os.ModePerm)
			if err != nil {
				return err
			}
			err = copyDirectory(srcFile, dstFile)
			if err != nil {
				return err
			}
		} else {
			err = copyFile(srcFile, dstFile)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func appendToFile(filePath string, line string) {
	// Open file in append mode
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// Create a writer
	writer := bufio.NewWriter(file)

	// Write the line to the file
	_, err = writer.WriteString(line)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}

	// Flush the buffer to ensure the line is written to the file
	err = writer.Flush()
	if err != nil {
		fmt.Println("Error flushing writer:", err)
		return
	}
}

func replaceLine(filePath string, search string, replace string) error {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	tempFile, err := os.CreateTemp("", "tempFile")
	if err != nil {
		return err
	}
	defer tempFile.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, search) {
			line = strings.Replace(line, search, replace, 1)
		}
		tempFile.WriteString(line + "\n")
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if err := os.Rename(tempFile.Name(), filePath); err != nil {
		return err
	}

	return nil
}

// func replaceStringInFile(filePath string, find string, replace string) {
// 	// Open the file for reading and writing
// 	file, err := os.OpenFile(filePath, os.O_RDWR, 0644)
// 	if err != nil {
// 		fmt.Println("Error:", err)
// 		return
// 	}
// 	defer file.Close()

// 	file2, err := os.OpenFile(filePath+"_new", os.O_RDWR|os.O_CREATE, 0644)
// 	if err != nil {
// 		fmt.Println("Error:", err)
// 		return
// 	}
// 	defer file.Close()

// 	// Create a scanner to read from the file
// 	scanner := bufio.NewScanner(file)

// 	// Create a writer to write to the same file
// 	writer := bufio.NewWriter(file2)

// 	// Keep track of line number
// 	lineNumber := 0

// 	// Loop through each line in the file
// 	for scanner.Scan() {
// 		lineNumber++
// 		line := scanner.Text()

// 		// Modify specific lines
// 		if strings.Contains(line, find) {
// 			_, err := writer.WriteString(replace + "\n")
// 			if err != nil {
// 				fmt.Println("Error writing to file:", err)
// 				return
// 			}
// 		} else {
// 			// If the line doesn't need to be modified, just write it back as is
// 			_, err := writer.WriteString(line + "\n")
// 			if err != nil {
// 				fmt.Println("Error writing to file:", err)
// 				return
// 			}
// 		}
// 	}

// 	// Check for any scanning errors
// 	if err := scanner.Err(); err != nil {
// 		fmt.Println("Error reading file:", err)
// 		return
// 	}

// 	// Flush the writer to ensure all data is written to the file
// 	err = writer.Flush()
// 	if err != nil {
// 		fmt.Println("Error flushing writer:", err)
// 		return
// 	}

// 	// Replace original

// }

func runCommand(binary string, args []string, envVariables ...string) (string, error) {
	var (
		stdErrBuffer bytes.Buffer
		stdOutBuffer bytes.Buffer
	)

	cmd := exec.Command(binary, args...)
	cmd.Stderr = &stdErrBuffer
	cmd.Stdout = &stdOutBuffer
	cmd.Env = append(os.Environ(), envVariables...)

	err := cmd.Run()
	if stdErrBuffer.Len() > 0 {
		return "", errors.New(stdErrBuffer.String())
	} else if err != nil {
		return "", err
	}

	return stdOutBuffer.String(), nil
}
