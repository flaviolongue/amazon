pipeline {
  agent any // Ou um agente específico com label 'java-agent'

  environment {
    GIT_CREDENTIALS_ID = 'github-token'
    DEFECTDOJO_URL = 'https://defectodojo.dev4cloud.online'
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

    stage('Trivy Dependencies') {
      steps {
        sh '''
          echo "Iniciando Trivy Dependencies Scan..."
          mkdir -p reports
          # Instala o Trivy
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -
          # Executa o scan de dependências
          ./bin/trivy fs . \
            --scanners vuln \
            --vuln-type library \
            --format json \
            --output reports/trivy-deps.json
          echo "Trivy Dependencies Scan concluído."
        '''
      }
    }

    stage('Gerar SBOM com Syft') {
        steps {
            sh '''
                echo "Iniciando geração de SBOM com Syft..."
                mkdir -p reports
                # Instala o Syft
                curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "${WORKSPACE}/tools_bin"
                # Gera SBOM no formato CycloneDX JSON
                ${WORKSPACE}/tools_bin/syft . -o cyclonedx-json > reports/sbom.json
                echo 'SBOM gerado com sucesso: reports/sbom.json'
            '''
        }
    }

    stage('Escanear SBOM com Grype') {
        steps {
            sh '''
                echo "Iniciando scan de SBOM com Grype..."
                mkdir -p reports
                # Instala o Grype
                curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b "${WORKSPACE}/tools_bin"
                # Escaneia o SBOM gerado pelo Syft e gera relatório SARIF
                ${WORKSPACE}/tools_bin/grype sbom.json -o sarif > reports/grype-report.sarif
                echo 'Relatório de vulnerabilidades Grype gerado: reports/grype-report.sarif'
            '''
        }
    }

    stage('Snyk CLI Scan') {
        steps {
            script {
                echo "Iniciando Snyk CLI Scan..."
                sh '''
                    mkdir -p reports
                    # Instala o Snyk CLI (via npm, requer Node.js no agente)
                    # Se Node.js não estiver disponível, você pode baixar o binário diretamente:
                    # curl https://static.snyk.io/cli/latest/snyk-linux -o /usr/local/bin/snyk && chmod +x "${WORKSPACE}/tools_bin"
                    npm install -g snyk
                '''
                // Autentica o Snyk CLI usando o token de API do Jenkins Credentials
                sh "${WORKSPACE}/tools_bin/snyk auth ${SNYK_TOKEN}"
                // Executa o scan de dependências do Snyk
                // '|| true' para que a etapa não falhe imediatamente se vulnerabilidades forem encontradas
                sh "${WORKSPACE}/tools_bin/snyk test --all-projects --json-file=reports/snyk-report.json || true"
                echo 'Relatório Snyk gerado: reports/snyk-report.json'
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
        // Arquiva todos os relatórios gerados para fácil acesso no Jenkins
        archiveArtifacts artifacts: 'reports/*', fingerprint: true
        script{
          def DATA_FINAL = sh(script: "date +%F", returnStdout: true).trim()
        }
        // Enviar OWASP Dependency-Check
        sh """
          echo "Enviando relatório OWASP Dependency-Check para DefectDojo..."
          curl -X POST "${DEFECTDOJO_URL}/api/v2/import-scan/" \
            -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
            -F "engagement=$ENGAGEMENT_ID" \
            -F "scan_type=Dependency Check Scan" \
            -F "minimum_severity=Low" \
            -F "active=true" \
            -F "verified=true" \
            -F "file=@reports/dependency-check-report.xml" \
            -F "scan_date=$DATA_FINAL" \
            -F "tags=sca,owasp" \
            -F "close_old_findings=false" \
            -F "description=Relatório gerado pelo OWASP Dependency-Check (POC SCA)"
          echo "Relatório OWASP Dependency-Check enviado."
        """

        // Enviar Trivy
        sh """
          echo "Enviando relatório Trivy para DefectDojo..."
          curl -X POST "${DEFECTDOJO_URL}/api/v2/import-scan/" \
            -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
            -F "engagement=$ENGAGEMENT_ID" \
            -F "scan_type=Trivy Scan" \
            -F "minimum_severity=Low" \
            -F "active=true" \
            -F "verified=true" \
            -F "file=@reports/trivy-deps.json" \
            -F "scan_date=$DATA_FINAL" \
            -F "tags=sca,trivy" \
            -F "close_old_findings=false" \
            -F "description=Relatório gerado pelo Trivy (POC SCA)"
          echo "Relatório Trivy enviado."
        """

        // Enviar SBOM (Syft)
        sh """
          echo "Enviando SBOM (Syft) para DefectDojo..."
          curl -X POST "${DEFECTDOJO_URL}/api/v2/import-scan/" \
            -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
            -F "engagement=$ENGAGEMENT_ID" \
            -F "scan_type=CycloneDX Scan" \
            -F "minimum_severity=Low" \
            -F "active=true" \
            -F "verified=true" \
            -F "file=@reports/sbom.json" \
            -F "scan_date=$DATA_FINAL" \
            -F "tags=sca,syft,sbom" \
            -F "close_old_findings=false" \
            -F "description=SBOM gerado pelo Syft (POC SCA)"
          echo "SBOM (Syft) enviado."
        """

        // Enviar Grype
        sh """
          echo "Enviando relatório Grype para DefectDojo..."
          curl -X POST "${DEFECTDOJO_URL}/api/v2/import-scan/" \
            -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
            -F "engagement=$ENGAGEMENT_ID" \
            -F "scan_type=SARIF" \
            -F "minimum_severity=Low" \
            -F "active=true" \
            -F "verified=true" \
            -F "file=@reports/grype-report.sarif" \
            -F "scan_date=$DATA_FINAL" \
            -F "tags=sca,grype" \
            -F "close_old_findings=false" \
            -F "description=Relatório gerado pelo Grype (POC SCA)"
          echo "Relatório Grype enviado."
        """

        // Enviar Snyk
        sh """
          echo "Enviando relatório Snyk para DefectDojo..."
          curl -X POST "${DEFECTDOJO_URL}/api/v2/import-scan/" \
            -H "Authorization: Token ${DEFECTDOJO_API_KEY}" \
            -F "engagement=$ENGAGEMENT_ID" \
            -F "scan_type=Snyk Scan" \
            -F "minimum_severity=Low" \
            -F "active=true" \
            -F "verified=true" \
            -F "file=@reports/snyk-report.json" \
            -F "scan_date=$DATA_FINAL" \
            -F "tags=sca,snyk" \
            -F "close_old_findings=false" \
            -F "description=Relatório gerado pelo Snyk CLI (POC SCA)"
          echo "Relatório Snyk enviado."
        """
      }
    }
  }

  post {
      always {
          echo 'Pipeline de SCA concluída.'
          // Limpar arquivos gerados, se necessário
          sh 'rm -rf reports dc bin snyk-report.json sbom.json grype-report.sarif'
      }
      failure {
          echo 'Pipeline de SCA falhou!'
          // Adicione aqui lógica para notificação de falha
      }
  }
}
