package iuh.fit.se.dtos.dashboard;

public class ChartDataDTO {
    private String label;
    private Double value;
    private Long count;

    public ChartDataDTO(String label, Double value, Long count) {
        this.label = label;
        this.value = value;
        this.count = count;
    }

    public ChartDataDTO(String label, Double value) {
        this.label = label;
        this.value = value;
    }

    // Getters & Setters
    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public Double getValue() {
        return value;
    }

    public void setValue(Double value) {
        this.value = value;
    }

    public Long getCount() {
        return count;
    }

    public void setCount(Long count) {
        this.count = count;
    }
}