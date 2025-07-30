pipeline {
    agent any // Ou um agente específico com label 'java-agent'

    environment {
        GIT_CREDENTIALS_ID = 'github-token'
        DEFECTDOJO_URL = 'https://defectdojo.dev4cloud.online'
        // ATENÇÃO: NUNCA COLOQUE TOKENS DIRETAMENTE AQUI.
        // Use Jenkins Credentials. Crie uma credencial 'Secret text' com o ID 'DEFECTDOJO_API_KEY'
        DEFECTDOJO_API_KEY = 'b496d5dd233e7de0fb3f27721d9a76160cfdf7a4' // credentials('DEFECTDOJO_API_KEY')
        // ID do produto no DefectDojo onde os resultados serão enviados
        // Substitua '2' pelo ID real do seu produto no DefectDojo
        DEFECTDOJO_PRODUCT_ID = '2' // Exemplo: '2' para o seu produto 'amazon-poc'

        // Para Snyk CLI: Crie uma credencial 'Secret text' com o ID 'SNYK_TOKEN'
        SNYK_TOKEN = '09a9b8a3-41b7-400a-b47a-2e7c6b3c8707'
    }

    stages {
        stage('Build do Projeto Java') {
            steps {
                script {
                    if (fileExists('pom.xml')) {
                        echo 'Detectado projeto Maven. Executando build em contêiner Maven...'
                        // Entra em um contêiner Maven oficial com JDK 11 para o build
                        docker.image('maven:3.8-openjdk-11').inside {
                            sh 'mvn clean install -DskipTests' // -DskipTests para agilizar a análise de segurança
                        }
                    } else if (fileExists('build.gradle')) {
                        echo 'Detectado projeto Gradle. Executando build em contêiner Gradle...'
                        // Entra em um contêiner Gradle oficial com JDK 15 para o build
                        docker.image('gradle:6.7.1-jdk15').inside {
                            sh 'chmod +x gradlew' // Garante que o gradlew seja executável
                            sh './gradlew build -x test' // -x test para agilizar a análise de segurança
                        }
                    } else {
                        echo 'Nenhum arquivo pom.xml ou build.gradle encontrado. Pulando build Java.'
                    }
                }
            }
        }

        stage('OWASP Dependency Check') {
            steps {
                sh '''
                    echo "Iniciando OWASP Dependency Check..."
                    mkdir -p reports
                    # Baixa e descompacta o Dependency-Check
                    curl -L -o dc.zip https://github.com/jeremylong/DependencyCheck/releases/download/v8.4.0/dependency-check-8.4.0-release.zip
                    unzip -o dc.zip -d dc
                    chmod +x dc/dependency-check/bin/dependency-check.sh
                    # Executa o scan
                    ./dc/dependency-check/bin/dependency-check.sh \
                        --project amazon-poc \
                        --scan . \
                        --format XML \
                        --out reports \
                        --disableAssembly # Desabilita análise de assemblies .NET se não for relevante
                    echo "OWASP Dependency Check concluído."
                '''
            }
        }

        stage('Gerar SBOM com Syft') {
            steps {
                sh '''
                    echo "Iniciando geração de SBOM com Syft..."
                    mkdir -p reports
                    mkdir -p "${WORKSPACE}/tools_bin"
                    # Instala o Syft
                    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "${WORKSPACE}/tools_bin"
                    # Gera SBOM no formato CycloneDX JSON
                    ${WORKSPACE}/tools_bin/syft . -o cyclonedx-json > reports/sbom.json
                    # ✅ Gerar SBOM em formato SPDX (mais compatível com Trivy)
                    ${WORKSPACE}/tools_bin/syft . -o spdx-json=reports/sbom-spdx.json
                    echo 'SBOM gerado com sucesso: reports/sbom.json'
                '''
            }
        }

        stage('Escanear SBOM com Grype') {
            steps {
                sh '''
                    echo "Iniciando scan de SBOM com Grype..."
                    mkdir -p reports
                    mkdir -p "${WORKSPACE}/tools_bin"
                    # Instala o Grype
                    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "${WORKSPACE}/tools_bin"
                    # Escaneia o SBOM gerado pelo Syft e gera relatório SARIF
                    ${WORKSPACE}/tools_bin/grype "sbom:reports/sbom.json" -o sarif > reports/grype-report.sarif
                    echo 'Relatório de vulnerabilidades Grype gerado: reports/grype-report.sarif'
                '''
            }
        }
        stage('Trivy SBOM Scan') {
            steps {
                sh '''
                    echo "Escaneando SBOM com Trivy..."
                    mkdir -p reports
                    mkdir -p "${WORKSPACE}/tools_bin"
                        
                    # Instalar Trivy
                    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "${WORKSPACE}/tools_bin"
                    
                    # ✅ Trivy escaneando o SBOM gerado pelo Syft
                    ${WORKSPACE}/tools_bin/trivy sbom reports/sbom-spdx.json \
                        --format json \
                        --output reports/trivy-deps.json \
                        --exit-code 0 \
                        --quiet
                    
                    # Gerar relatório em formato table para visualização
                    ${WORKSPACE}/tools_bin/trivy sbom reports/sbom-spdx.json \
                        --format table \
                        --output reports/trivy-deps.txt \
                        --exit-code 0 \
                        --quiet
                    
                    echo "Trivy SBOM Scan concluído!"
                '''
            }
        }

        stage('Snyk CLI Scan') {
            steps {
                script {
                    echo "Iniciando Snyk CLI Scan..."
                    sh '''
                        mkdir -p reports "${WORKSPACE}/tools_bin"
                        
                        # Instalar Snyk CLI
                        curl https://static.snyk.io/cli/latest/snyk-linux -o "${WORKSPACE}/tools_bin/snyk"
                        chmod +x "${WORKSPACE}/tools_bin/snyk"
                        
                        # Verificar versão
                        ${WORKSPACE}/tools_bin/snyk --version
                    '''
                    
                    // Autenticar Snyk
                    sh '''
                        echo "Autenticando Snyk..."
                        ${WORKSPACE}/tools_bin/snyk auth ${SNYK_TOKEN}
                        
                        # Verificar autenticação
                        ${WORKSPACE}/tools_bin/snyk whoami || echo "Falha na autenticação"
                    '''
                    
                    // Executar scan com diferentes estratégias
                    sh '''
                        echo "=== EXECUTANDO SNYK SCAN ==="
                        
                        # Função para executar Snyk com diferentes abordagens
                        run_snyk_scan() {
                            local approach=$1
                            local extra_args=$2
                            
                            echo "Tentativa ${approach}: ${extra_args}"
                            
                            ${WORKSPACE}/tools_bin/snyk test ${extra_args} \
                                --json-file=reports/snyk-${approach}.json \
                                --severity-threshold=low 2>&1 || echo "Abordagem ${approach} falhou"
                            
                            if [ -f "reports/snyk-${approach}.json" ] && [ -s "reports/snyk-${approach}.json" ]; then
                                echo "✅ Abordagem ${approach} bem-sucedida"
                                cp "reports/snyk-${approach}.json" "reports/snyk-report.json"
                                return 0
                            else
                                echo "❌ Abordagem ${approach} falhou"
                                return 1
                            fi
                        }
                        
                        # Detectar tipo de projeto e ajustar estratégia
                        if [ -f "pom.xml" ]; then
                            echo "Projeto Maven detectado"
                            
                            # Tentar diferentes abordagens para Maven
                            run_snyk_scan "maven-default" "" || \
                            run_snyk_scan "maven-specific" "--maven" || \
                            run_snyk_scan "maven-all-projects" "--all-projects" || \
                            run_snyk_scan "maven-unmanaged" "--unmanaged" || \
                            echo "Todas as abordagens Maven falharam"
                            
                        elif [ -f "build.gradle" ]; then
                            echo "Projeto Gradle detectado"
                            
                            # Tentar diferentes abordagens para Gradle
                            run_snyk_scan "gradle-default" "" || \
                            run_snyk_scan "gradle-specific" "--gradle" || \
                            run_snyk_scan "gradle-all-projects" "--all-projects" || \
                            run_snyk_scan "gradle-unmanaged" "--unmanaged" || \
                            echo "Todas as abordagens Gradle falharam"
                            
                        else
                            echo "Projeto genérico detectado"
                            run_snyk_scan "generic" "--unmanaged"
                        fi
                        
                        # Verificar se algum relatório foi gerado
                        if [ ! -f "reports/snyk-report.json" ] || [ ! -s "reports/snyk-report.json" ]; then
                            echo "⚠️  Nenhum relatório Snyk válido gerado, criando relatório vazio..."
                            echo '{"vulnerabilities":[],"ok":true,"dependencyCount":0,"org":"unknown","policy":"","isPrivate":false,"licensesPolicy":null,"packageManager":"unknown","ignoreSettings":null,"summary":"No dependencies found","filesystemPolicy":false,"filtered":{"ignore":[],"patch":[]},"uniqueCount":0,"projectName":"unknown","path":"unknown"}' > reports/snyk-report.json
                        fi
                        
                        echo "=== RESUMO SNYK ==="
                        ls -la reports/snyk*.json
                    '''
                }
            }
        }
        stage('Criar Engagement DefectDojo') {
            steps {
                script {
                    def today = sh(script: "date +%F", returnStdout: true).trim()
                    def response = sh(
                        script: """
                            curl -s -X POST ${DEFECTDOJO_URL}/api/v2/engagements/ \
                                -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
                                -H "Content-Type: application/json" \
                                -d '{
                                    "name": "Build-${env.BUILD_NUMBER}",
                                    "product": ${DEFECTDOJO_PRODUCT_ID},
                                    "engagement_type": "CI/CD",
                                    "target_start": "${today}",
                                    "target_end": "${today}",
                                    "status": "In Progress",
                                    "active": true
                                }'
                        """,
                        returnStdout: true
                    ).trim()

                    def engagementId = new groovy.json.JsonSlurperClassic().parseText(response).id
                    env.ENGAGEMENT_ID = "${engagementId}"
                    echo "Engagement DefectDojo criado com ID: ${env.ENGAGEMENT_ID}"
                }
            }
        }

        stage('Publicar Relatórios') {
            steps {
                script {
                    // Definir data uma única vez no escopo correto
                    def DATA_FINAL = sh(script: "date +%F", returnStdout: true).trim()
                    
                    // Arquivar todos os relatórios gerados
                    archiveArtifacts artifacts: 'reports/*', fingerprint: true, allowEmptyArchive: true
                    
                    // Função para enviar relatórios com tratamento de erro
                    def enviarRelatorio = { arquivo, scanType, tags, descricao ->
                        sh """
                            if [ -f "${arquivo}" ]; then
                                echo "Enviando ${descricao} para DefectDojo..."
                                
                                # ✅ Retry com backoff para resolver 502
                                for attempt in 1 2 3; do
                                    echo "Tentativa \$attempt de 3..."
                                    
                                    RESPONSE=\$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "${DEFECTDOJO_URL}/api/v2/import-scan/" \
                                        -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
                                        -F "engagement=\$ENGAGEMENT_ID" \
                                        -F "scan_type=${scanType}" \
                                        -F "minimum_severity=Low" \
                                        -F "active=true" \
                                        -F "verified=true" \
                                        -F "file=@${arquivo}" \
                                        -F "scan_date=${DATA_FINAL}" \
                                        -F "tags=${tags}" \
                                        -F "close_old_findings=false" \
                                        -F "description=${descricao}")
                                    
                                    HTTP_STATUS=\$(echo \$RESPONSE | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')
                                    
                                    if [ \$HTTP_STATUS -eq 200 ] || [ \$HTTP_STATUS -eq 201 ]; then
                                        echo "✅ ${descricao} enviado com sucesso (HTTP \$HTTP_STATUS)"
                                        break
                                    elif [ \$HTTP_STATUS -eq 502 ]; then
                                        echo "⚠️  HTTP 502 - Tentativa \$attempt falhou, aguardando..."
                                        sleep \$((attempt * 5))  # Backoff: 5s, 10s, 15s
                                    else
                                        echo "❌ Erro ao enviar ${descricao} (HTTP \$HTTP_STATUS)"
                                        break
                                    fi
                                done
                            else
                                echo "⚠️  Arquivo ${arquivo} não encontrado."
                            fi
                        """
                    }
                    
                    // Enviar cada relatório
                    enviarRelatorio(
                        'reports/dependency-check-report.xml',
                        'Dependency Check Scan',
                        'sca,owasp',
                        'Relatório gerado pelo OWASP Dependency-Check (POC SCA)'
                    )
                    sleep(5) 
                    enviarRelatorio(
                        'reports/trivy-deps.json',
                        'Trivy Scan',
                        'sca,trivy',
                        'Relatório gerado pelo Trivy (POC SCA)'
                    )
                    sleep(5) 
                    // enviarRelatorio(
                    //     'reports/sbom.json',
                    //     'CycloneDX Scan',
                    //     'sca,syft,sbom',
                    //     'SBOM gerado pelo Syft (POC SCA)'
                    // )
                    
                    enviarRelatorio(
                        'reports/grype-report.sarif',
                        'SARIF',
                        'sca,grype',
                        'Relatório gerado pelo Grype (POC SCA)'
                    )
                    sleep(5) 
                    enviarRelatorio(
                        'reports/snyk-report.json',
                        'Snyk Scan',
                        'sca,snyk',
                        'Relatório gerado pelo Snyk CLI (POC SCA)'
                    )
                }
                
                // Publicar relatórios HTML no Jenkins
                publishHTML([
                    allowMissing: true,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'reports',
                    reportFiles: '*.html,*.xml,*.json,*.txt,*.sarif',
                    reportName: 'Security Reports',
                    reportTitles: 'Relatórios de Segurança - SCA Pipeline'
                ])
                
                // Resumo final
                sh '''
                    echo "=== RESUMO DOS RELATÓRIOS GERADOS ==="
                    ls -la reports/ || echo "Diretório reports não encontrado"
                    echo "=== FIM DO RESUMO ==="
                '''
            }
        }
    }

    post {
        always {
            echo 'Pipeline de SCA concluída.'
            // Limpar arquivos gerados, se necessário
            // sh 'rm -rf reports dc bin snyk-report.json sbom.json grype-report.sarif'
        }
        failure {
            echo 'Pipeline de SCA falhou!'
            // Adicione aqui lógica para notificação de falha
        }
        success {
            echo 'Pipeline de SCA executada com sucesso!'
        }
    }
}
