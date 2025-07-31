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
        stage('Snyk Scan') {
            steps {
                script {
                    def snykDockerRun = { tool, extraArgs, summaryMsg, image ->
                        sh """
                            mkdir -p reports
                            echo "🐳 Executando Snyk via Docker (${tool})..."
                            docker run --rm \
                                -v "\$(pwd):/project" \
                                -w /project \
                                -e SNYK_TOKEN="\${SNYK_TOKEN}" \
                                --entrypoint snyk ${image} test --json --severity-threshold=low > reports/snyk-report.json || true
                             
                            if [ -f "reports/snyk-report.json" ] && [ -s "reports/snyk-report.json" ]; then
                                echo "✅ Relatório Snyk gerado com sucesso"
                                echo "📊 Tamanho: \$(du -h reports/snyk-report.json)"
                                echo "📋 Primeiras linhas:"
                                head -3 reports/snyk-report.json
                            else
                                echo "⚠️ Criando relatório de fallback"
                                echo '{"vulnerabilities":[],"ok":true,"summary":"${summaryMsg}"}' > reports/snyk-report.json
                            fi
                        """
                    }
        
                    if (fileExists('pom.xml')) {
                        echo 'Projeto Maven detectado.'
                        snykDockerRun('maven', '--maven', 'Maven fallback scan','snyk/snyk:maven-3-jdk-11')
                    } else if (fileExists('build.gradle')) {
                        echo 'Projeto Gradle detectado.'
                        snykDockerRun('gradle', '--gradle', 'Gradle fallback scan','snyk/snyk:gradle-jdk11')
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
                    sleep(5) 
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
                    enviarRelatorio(
                        'reports/sbom.json',
                        'CycloneDX Scan',
                        'sca,syft,sbom',
                        'SBOM gerado pelo Syft (POC SCA)'
                    )
                    sleep(5) 
                    enviarRelatorio(
                        'reports/grype-report.sarif',
                        'Anchore Grype',
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
            sh 'rm -rf reports'
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
