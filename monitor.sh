#!/bin/bash
# Script de monitoring du collector

echo "📊 Monitoring AgentGuard..."
echo ""

while true; do
    clear
    echo "===== AgentGuard Dashboard ====="
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    
    # Métriques du collector
    METRICS=$(curl -s "http://localhost:8080/api/metrics" | python3 -m json.tool 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        echo "📡 SPANS TOTALES: $(echo "$METRICS" | grep total_spans | cut -d: -f2 | tr -d ', ')"
        echo "🛡️ BLOQUÉES: $(echo "$METRICS" | grep blocked_operations | cut -d: -f2 | tr -d ', ')"
        echo "🧠 DÉTECTION ML: $(echo "$METRICS" | grep avg_ml_score | cut -d: -f2 | tr -d ', ')"
        echo "🎯 LLM JUDGE: $(echo "$METRICS" | grep llm_judge_count | cut -d: -f2 | tr -d ', ')"
        echo "⚡ LATENCE: $(echo "$METRICS" | grep avg_latency_ms | cut -d: -f2 | tr -d ', ')"
    else
        echo "❌ Collector inaccessible"
    fi
    
    echo ""
    echo "🔄 Actualisation dans 5s... (Ctrl+C pour quitter)"
    sleep 5
done
