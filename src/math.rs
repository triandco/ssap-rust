use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

pub fn multiply(x: Vec<f32>, factor: f32) -> Vec<f32> {
    if x.len() == 0 {
        return Vec::new();
    }
    x.par_iter().map(|x| x * factor).collect()
}

pub fn sum(a: Vec<f32>, b: Vec<f32>) -> Vec<f32> {
    if a.len() != b.len() {
        panic!(
            "sum failed: vectors must be of the same length. But got {} and {}",
            a.len(),
            b.len()
        );
    }
    if a.len() == 0 {
        return Vec::new();
    }
    a.par_iter().zip(b.par_iter()).map(|(a, b)| a + b).collect()
}

pub fn minus(minuend: Vec<f32>, subtraend: Vec<f32>) -> Vec<f32> {
    if minuend.len() != subtraend.len() {
        panic!(
            "minus fail: vectors must be of the same length. But got {} and {}",
            minuend.len(),
            subtraend.len()
        );
    }
    if minuend.len() == 0 {
        return Vec::new();
    }
    minuend
        .par_iter()
        .zip(subtraend.par_iter())
        .map(|(a, b)| a - b)
        .collect()
}

pub fn normalise(value: Vec<f32>) -> Vec<f32> {
    if value.len() == 0 {
        return Vec::new();
    }
    let vec_length = value.par_iter().map(|x| x * x).sum::<f32>().powf(0.5);
    value.par_iter().map(|x| x / vec_length).collect()
}
