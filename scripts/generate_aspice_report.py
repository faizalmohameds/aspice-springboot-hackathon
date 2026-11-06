- name: Download SonarCloud Measures
  if: always()
  env:
    SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
    SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
    SONAR_PROJECT_KEY: ${{ secrets.SONAR_PROJECT_KEY }}
  run: |
    mkdir -p sonar-evidence

    curl --fail --silent --show-error \
      -u "$SONAR_TOKEN:" \
      "$SONAR_HOST_URL/api/measures/component?component=$SONAR_PROJECT_KEY&metricKeys=coverage,bugs,vulnerabilities,code_smells,security_hotspots,duplicated_lines_density,sqale_index,reliability_rating,security_rating,sqale_rating,ncloc" \
      -o sonar-evidence/sonar-measures.json

    curl --fail --silent --show-error \
      -u "$SONAR_TOKEN:" \
      "$SONAR_HOST_URL/api/qualitygates/project_status?projectKey=$SONAR_PROJECT_KEY" \
      -o sonar-evidence/sonar-quality-gate.json

    curl --fail --silent --show-error \
      -u "$SONAR_TOKEN:" \
      "$SONAR_HOST_URL/api/issues/search?componentKeys=$SONAR_PROJECT_KEY&resolved=false&ps=500" \
      -o sonar-evidence/sonar-issues.json