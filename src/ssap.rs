use rand::Rng;
use rand_distr::{Distribution, Normal};
use crate::math::{multiply, sum};

/// SAP vector hash is based on the encryption method of SAP scheme
/// described in Approximate-Distance-Comparision Preserving Symmetric Encryption
/// to produced a hashed vector using a pertubation and a scale factor
/// in a way that preserve its approximate-distance-comparision property
#[derive(Clone)]
pub struct NormalisedVector{
    pub value: Vec<f32>
}

impl NormalisedVector{
    pub fn new(dimension: usize) -> Self{
        let mut rng = rand::rng();
        let normal = Normal::new(0.0, 1.0).unwrap();
        let mut u: Vec<f32> = Vec::with_capacity(dimension);
        for _ in 0..dimension {
            u.push(normal.sample(&mut rng));
        }

        Self {
            value: crate::math::normalise(u)
        }
    }

    
    pub fn from_vec(value: Vec<f32>) -> Self {
        Self {
            value: crate::math::normalise(value)
        }
    }
}

#[derive(Clone)]
pub struct EncryptionKey{
    pertubation_direction: NormalisedVector,
    scale_factor: f32,
    beta: f32
}

impl EncryptionKey{
    pub fn new(dimension: usize, beta: f32, scale_factor: f32) -> Self {
        Self {
            beta,
            pertubation_direction: NormalisedVector::new(dimension),
            scale_factor
        }
    }
}

pub fn encrypt(key: &EncryptionKey, value: Vec<f32>) -> Vec<f32> {
    let rand_factor: f32 = rand::rng().random_range(0.0..1.0);
    let pertubation_scale = key.beta / 4.0 * rand_factor.powf(1.0 / value.len() as f32);
    let pertubation = multiply(key.pertubation_direction.value.clone(), pertubation_scale);
    multiply(
        sum(value, pertubation), 
        key.scale_factor
    ) 
}

#[cfg(test)]
mod test{
    use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

    use super::*;
    
    fn dot_distance(a: &Vec<f32>, b: &Vec<f32>) -> f32 {
        assert_eq!(
            a.len(),
            b.len(),
            "Can't calculate the 2d norm if the number of a and b components doesn't match"
        );
        a.par_iter()
            .zip(b.par_iter())
            .map(|(a, b)| (a * b))
            .sum()
    }

    #[test]
    /// Beta preserve distance comparison property is defined as 
    /// dist(x,y) < dist(x,z) - beta => dist(encrypt(x), encrypt(y)) < dist(encrypted(x), encrypted(z))
    fn approximate_distance_comparison_preserving_by_beta() {
        let dimension = 384;

        // x is an AllMiniLM12V2 embedding of the item id 4983 in Scifact corpus
        let x = vec![0.02132726, -0.06046767, 0.018071115, 0.016465398, -0.035991255, 0.056629427, -0.1229082, 0.04071608, 0.025057262, -0.009722404, 0.008161747, -0.087237954, -0.0046114926, 0.05100355, -0.062485892, -0.018280994, -0.04662518, -0.07116288, -0.08197386, -0.027495023, 0.0339726, 0.030501794, 0.029502857, -0.04355334, -0.056483682, 0.09257982, -0.00016747945, -0.12541786, 0.053123713, -0.08570873, -0.019135527, -0.03328306, 0.073367, -0.11334835, 0.10849911, 0.024310684, 0.10863749, 0.070339836, -0.017945666, -0.011771061, 0.045536827, 0.025282128, 0.025451602, 0.08306969, 0.013666284, 0.06537896, 0.06316831, 0.013103954, 0.02318911, -0.025783073, -0.041854594, -0.028199486, -0.022973819, 0.055635937, -0.013660455, 0.09498659, 0.07380787, 0.0023575977, 0.033095423, -0.014405893, -0.05378341, 0.073873445, 0.0054328507, -0.030045021, 0.009702578, 0.042911626, -0.009904916, -0.02673475, 0.00916779, -0.012231227, 0.10762139, 0.037673805, 0.047765404, 0.030284254, 0.018097213, 0.03996987, 0.05731548, 0.097822696, 0.09228386, -0.042609107, 0.038666587, 0.07685432, 0.03597501, 0.08635094, -0.014927099, 0.095629975, -0.021265965, 0.015413742, -0.12250316, -0.10767309, -0.065120265, 0.048617784, -0.09605669, 0.057717662, -0.011932433, 0.037324112, -0.08538011, 0.023284657, 0.003816929, -0.021109752, -0.027965058, -0.02923732, -0.052256465, 0.05740109, 0.023471057, -0.0030767885, -0.041717846, 0.015566266, 0.011704114, 0.002817586, 0.004267862, 0.030804532, -0.102551386, 0.06429462, 0.0065758363, -0.065901056, 0.002424787, 0.06412828, 0.06300755, 0.010372092, -0.0082620485, -0.061657965, 0.0051043434, -0.064461626, 0.04472566, -0.09266137, 0.008183777, 0.032045502, 0.051156852, 0.0032435344, -0.07869313, -0.029679209, -0.033897992, -0.05825099, 0.08799686, 0.014743472, -0.016010983, 0.048424017, -0.009586568, -0.017161861, -0.021934869, 0.13816506, -0.0023213245, 0.038129065, 0.021570276, -0.0033527303, -0.006231949, -0.04748213, 0.021921664, 0.037436295, -0.02865844, 0.0026104602, 0.004757667, -0.01579354, -0.043786846, 0.103955396, -0.033524282, -0.031919036, 5.2034928e-5, 0.01955554, -0.025579527, -0.006032145, -0.09282742, -0.020877134, 0.011427662, -0.005428133, 0.008866444, -0.01140242, 0.017201835, -0.020500902, -0.054412648, 0.072472766, -0.03530309, 0.056932908, -0.019188033, 0.008795174, -0.060221303, 0.008263948, -0.012118126, -0.07676807, 0.0071201897, -0.0042304844, -0.07225077, -0.047153916, -0.031134494, 0.025572682, -0.0014437139, -0.08513447, -0.013969387, -0.0654635, -0.048434578, 0.06059734, 0.046100195, -0.08013195, -0.063026585, 0.06230875, 0.016770376, -0.028404625, 0.03486219, -0.049707185, -0.009845041, 0.007605819, -0.008470729, 0.033214714, 0.06969589, 0.043271992, -0.089186, 0.033549313, -0.046467688, -0.01795204, -0.0358889, -0.0038064457, -0.06474716, 0.06132093, 0.023058638, 0.11159808, -0.038500864, -0.049286358, 0.086521916, 0.007039777, 0.033099957, 0.0019243596, -0.048862483, 5.0782726e-33, -0.08125857, 0.004214493, 0.004277107, 0.056147028, -0.02269295, 0.071363755, 0.10691939, 0.13750415, 0.04954808, -0.01776464, 0.050576113, -0.1117966, -0.059965137, -0.039437313, -0.026189262, 0.0537272, 0.014704846, 0.07573535, 0.019549508, 0.036015842, -0.00977432, 0.13628876, -0.030071236, 0.029088998, 0.07587067, 0.06086127, -0.03751799, 0.0046450645, -0.01713896, -0.011262208, 0.009937063, 0.0360207, 0.066346966, -0.031809468, 0.017677506, -0.008436381, -0.034650054, -7.435514e-5, -0.039119102, -0.03269577, 0.037411842, 0.046602514, 0.022803629, -0.09054749, 0.028235093, 0.020667847, -0.03716119, 0.02498037, 0.035708714, 0.034158338, -0.017098442, -0.03729911, -0.04415717, -0.043080926, -0.014474024, 0.083971, 0.020854004, -0.046696767, 0.011163503, -0.027325286, 0.077448644, -0.03197286, -0.12095242, -0.03593892, -0.0076933936, 0.090132184, -0.03667569, -0.0755724, 0.027795298, 0.044305053, -0.042856097, 0.032209504, -0.032333285, 0.0146633135, -0.042310048, -0.0820925, 0.026500393, -0.01264212, -0.058862723, 0.07629578, -0.004742748, 0.0113577135, 0.006775918, 0.026164822, 0.048944216, -0.030185014, -0.0032350067, -0.097863, -0.08564037, -0.088580936, -0.051803757, -0.054211695, -0.039208315, -0.012875607, -0.09257497, 5.6525086e-32, 0.067981236, -0.046236854, 0.021017991, 0.022736337, 0.018277962, -0.018715449, 0.032076336, 0.022803452, 0.009491485, -0.0037282307, -0.019237237, -0.033609495, -0.06915459, -0.088029556, 0.052735515, -0.01140413, 0.069646955, 0.050267763, 0.0075001353, -0.092086315, 0.051432233, 0.0218681, 0.08029854, -0.0046422645, 0.067375995, 0.0034444479, 0.06352888, -0.04611326, -0.06480018, -0.047305077, 0.045306575, 0.03072321, 0.03318382, 0.017228143, -0.0023645568, -0.047216102, 0.039284967, -0.009874005, -0.0990151, 0.08312275, 0.043313842, -0.053192727, -0.019196238, -0.031419415, 0.016219977, 0.028178342, 0.001365299, 0.036343463, -0.028769571, -0.04756825, -0.026771491, 0.015514112, -0.04366901, -0.0028888232, -0.049454886, 0.003796222, -0.037016764, 0.08775572, 0.0027852524, -0.019999772, -0.12578502, 0.046791732, 0.053357437, -0.057687704];
        // y is an AllMiniLM12V2 embedding of the item id 425 in Scifact queries
        let y = vec![-0.0002184998, -0.076994464, -0.056080014, 0.107117675, -0.019247916, 0.0998099, -0.04790933, 0.011857075, -0.041302577, 0.07691275, 0.08679678, -0.038827084, 0.07621808, -0.035086088, 0.013191, -0.02909983, -0.05330775, -0.110713154, 0.028071506, 0.009523307, 0.020851454, -0.013582963, 0.08141597, -0.012509563, 0.0030922967, 0.03595089, -0.0115848435, -0.012837177, 0.071904786, -0.0047777086, -0.0233579, -0.05904924, 0.017537007, -0.065868735, 0.015912173, 0.028922476, 0.056926403, 0.049480952, -0.036427997, 0.051698297, -0.05005147, -0.016095944, -0.055759344, 0.025810225, -0.027620822, 0.06687514, -0.058442842, 0.04684116, 0.06310132, 0.050232936, -0.082444884, 0.037958685, 0.040579945, 0.06853329, 0.014509808, -0.057558395, 0.055573665, -0.018893791, -0.0090529695, 0.0118368715, 0.010531178, -0.04933995, 0.026207574, -0.026342299, -0.03611868, 0.06564686, 0.065417826, -0.04354932, -0.067292616, 0.018080035, 0.037513547, 0.048271507, 0.07478185, 0.0964546, 0.0743693, 0.011421014, -0.043905273, 0.016458388, 0.06791556, -0.0745524, 0.005864336, 0.03613731, 0.053782433, 0.0264236, 0.021214362, 0.10160016, 0.0021766922, 0.040976588, -0.05505017, -0.004363967, -0.056621008, 0.043512855, 0.03715842, 0.030355256, -0.07420221, 0.048227903, 0.03402167, -0.03399156, -0.06551553, -0.054935638, -0.06581098, 0.098798245, 0.015703602, 0.088619724, -0.052870926, 0.085992396, 0.004926812, -0.047270983, -0.026431926, -0.018016277, -0.01570211, -0.018136462, 0.016403392, 0.007622656, -0.07676237, -0.08717052, -0.019069811, -0.013554414, 0.12254633, 0.08194351, -0.013478025, 0.011711019, 0.074576795, -0.020990519, -0.0041308496, 0.0030261483, -0.03113252, -0.055346146, 0.062360514, -0.019683192, -0.05492859, 0.03712827, -0.029014323, -0.060033303, 0.05413923, -0.026318984, 0.05162884, -0.029072614, 0.0014123012, -0.082246356, 0.06465754, 0.02817336, -0.047965482, -0.09100325, -0.0017702273, 0.027642585, -0.010889725, 0.060918335, -0.015971389, -0.010886736, -0.053672925, 0.035306677, 0.035316687, 0.044719078, 0.0340737, 0.08480352, 0.025518158, 0.032267794, 0.030081416, -0.0120051475, 0.08774251, -0.04252058, -0.07561428, -0.014389967, 0.058787204, 0.010826384, 0.009964536, 0.057420198, -0.061135937, -0.009508528, -0.0065144924, 0.03231503, -0.028498579, 0.018273758, 0.028642349, -0.09938844, -0.046458658, -0.04101015, -0.0054193144, 0.0027987075, -0.088569954, 0.04858009, 0.02852166, -0.0038439136, -0.020422459, 0.08534856, 0.023529546, 0.014436284, -0.026068732, -0.091018446, -0.04781741, -0.040884875, 0.054743297, -0.0013717442, -0.010458617, 0.09742464, -0.07406965, 0.022833344, 0.009670576, -0.06962826, -0.030036487, -0.02842837, -0.050750986, 0.07253088, 0.06951125, -0.014396645, -0.05650022, -0.02605634, 0.071669586, 0.020362861, -0.026984883, -0.036024116, 0.06277442, -0.060254503, -0.13303901, 0.029794717, -0.0702376, -0.0063601728, 0.0122771915, -0.030933997, 0.029387835, 0.03576982, -0.043628044, 1.01670586e-32, -0.0641943, 0.029710792, -0.020507261, -0.0067832293, -0.0112750875, 0.049628843, 0.015400387, 0.009504789, 0.0143339895, -0.07901652, 0.051286247, -0.15433295, 0.0005934973, -0.05743137, -0.008570838, 0.057065014, -0.108371645, 0.05920107, -0.0017661446, 0.006817909, 0.10215077, 5.870766e-5, 0.0020806268, 0.025426785, -0.013222454, 6.2973224e-5, -0.051926125, 0.027188303, -0.052950267, -0.018043373, 0.07995591, 0.029961571, 0.014825, -0.04453345, -0.04224783, -0.009894265, -0.06786795, 0.08029932, 0.0302402, 0.0017075083, 0.03721648, -0.03303039, 0.041249163, -0.093807824, -0.015628602, -0.06595712, 0.015811753, -0.002881751, 0.06314554, -0.07976206, -0.017629508, 0.014230623, -0.044976585, 0.038713314, -0.0035873961, 0.04784006, 0.03673239, -0.05495893, 0.04926119, -0.17489213, -0.017439265, 0.048040416, -0.024034113, -0.0058415155, -0.08096406, -0.001549914, -0.012646903, -0.09339697, 0.017661037, 0.030423641, -0.004941524, 0.028749915, 0.019181868, 0.0136759635, -0.020789204, 0.017419122, -0.033506334, 0.037023768, 0.03537039, 0.044975106, -0.0067137154, -0.046994347, 0.09559562, 0.003687155, -0.030210352, 0.017899832, -0.0017883312, -0.06305183, -0.053345848, -0.017832076, -0.08757558, 0.042216793, 0.05628852, -0.08189297, -0.023196684, 3.900753e-32, 0.014995653, -0.042914234, -0.054307066, 0.11603947, -0.0036335015, 0.0027646017, 0.016742844, 0.032807287, 0.032677203, 0.043608647, -0.0008847043, -0.029372578, -0.008135738, -0.018281285, 0.003750152, 0.0044601937, 0.035309996, 0.10566135, -0.039044138, -1.3709281e-6, 0.06389639, 0.03131851, 0.14459147, 0.012828883, 0.095121615, -0.08944029, -0.01669879, 0.04230963, -0.07819373, 0.007920689, 0.0017840818, -0.002553041, -0.02045068, 0.04125978, 0.075759366, -0.110402144, -0.03054905, 0.038294982, 0.0055754147, 0.07342113, -0.04075054, -0.038668066, -0.03992548, 0.0077933604, 0.059016295, -0.07570712, -0.07772499, -0.0092600165, 0.11117649, 0.017637182, 0.014457688, -0.039874133, -0.09128853, -0.036493465, -0.00298751, 0.080940075, -0.006529885, 0.017366908, -0.0618523, -0.05887384, -0.020333806, 0.08716107, 0.060358632, -0.05318747];
        // z is an AllMiniLM12V2 embedding of the item id 5836 in Scifact corpus
        let z = vec![-0.018142674, 0.008231663, 0.027027896, -0.022050738, 0.0026696434, 0.032641187, 0.0043796925, 0.014679285, -0.062700145, 0.08055287, -0.08715872, -0.009624308, 0.0040125274, -0.050071884, -0.09662376, 0.08317187, 0.019996272, 0.030915026, -0.084509335, 0.020194583, -0.046351604, 0.024829434, -0.061121877, -0.032907967, -0.009364599, -0.031302974, 0.055335425, -0.031136261, -0.03201566, -0.034576964, 0.04753405, 0.027432175, 0.03959413, -0.034207884, -0.026706768, 0.01082148, -0.024611033, 0.026426679, -0.066371135, -0.020684246, -0.015729975, 0.050379753, 0.05162716, 0.058630623, 0.0844875, -0.055864345, 0.03544938, -0.0352402, -0.060448773, 0.06038769, 0.05761476, 0.029638352, 0.032499164, -0.0033013136, -0.024319826, 0.08375487, -0.089650005, 0.042011287, -0.015868215, -0.0414406, -0.11869833, -0.056666534, -0.022727, 0.024039086, -0.03039684, -0.02663845, -0.028639123, 0.004692389, -0.06622648, -0.06736186, -0.013709947, 0.096277595, -0.015478016, 0.01739057, 0.014543963, 0.08753422, 0.07999701, 0.013360514, 0.12265096, -0.024698822, -0.031066794, -0.008653025, 0.050721183, -0.0082227755, -0.00906248, 0.04150291, -0.012248581, -0.06869508, 0.02680555, -0.018797103, -0.019188384, -0.040897302, 0.0015573738, 0.04271179, -0.0070172586, 0.055138223, 0.0431415, -0.026613057, -0.032460243, -0.022534028, -0.01425927, 0.031878036, -0.00020237392, 0.019852176, -0.053015895, -0.045205366, 0.012407248, 0.06543327, -0.00021162117, 0.01803951, 0.009581623, -0.035888422, 0.03250767, 0.03285682, 0.016795853, -0.0043788026, -0.008354093, 0.009385768, -0.009451143, -0.10626278, -0.02895533, 0.032546625, -0.059409138, 0.053721637, -0.007054125, -0.023668025, 0.0249099, 0.03483825, 0.03607999, 0.0058638314, -0.020523174, 0.14338844, 0.010829504, -0.054986943, -0.06395406, -0.022782654, -0.118274935, -0.010135516, -0.077527754, -0.0183209, 0.07821689, -0.024398869, -0.0060924124, -0.017534401, -0.028185364, -0.062014885, 0.0111374445, -0.010329739, -0.014171816, -0.019204032, 0.07509571, -0.043242298, -0.006768984, 0.108885735, -0.041484352, 0.019688074, -0.012093301, 0.03859935, -0.04978576, 0.021117402, 0.04427925, -0.117686994, -0.0925212, -0.024050387, 0.045852415, -0.073177196, -0.021760805, 0.04182336, 0.01776947, -0.045908008, -0.056045134, -0.043502085, -0.023398276, 0.005077675, 0.046760857, -0.015448204, -0.0667966, -0.0359879, 0.016443469, 0.04741649, -0.01777412, -0.00047904922, -0.09090214, -0.055738464, -0.043007877, -0.007906292, -0.03791092, 0.07073126, 0.02442508, -0.13558774, -0.012023056, 0.12111231, 0.06062028, -0.004289197, 0.0035128163, 0.032042984, -0.034983303, -0.0037546407, 0.076221585, 0.058841877, -0.007121222, 0.0458112, 0.09204336, 0.041353796, 0.038560417, 0.14403851, 0.031928185, 0.0028940493, 0.06894579, 0.006260487, -0.059965096, 0.07681567, 0.021144077, -0.032810085, 0.09009656, 0.021787109, 0.0874972, -0.011118911, -0.0034206475, -0.0815096, -0.014946304, -0.0034388173, -0.0598091, -1.0896019e-32, 0.07925094, 0.038125772, -0.026632408, -0.09643446, 0.004287942, -0.0046444903, 0.011995532, 0.040744834, 0.106876366, 0.03264686, 0.022942087, 0.08114423, -0.072249204, 0.007167532, -0.06939995, -0.04997562, -0.030533064, -0.06501943, -0.031330947, 0.075377345, 0.008987625, 0.021271806, -0.09576604, -0.012998302, 0.004329941, 0.042528857, -0.07691876, 0.059352312, 0.101895206, 0.074737296, -0.035523444, -0.009405564, -0.0100376755, -0.006954429, 0.05570851, -0.04759996, -0.0788421, 0.024905894, 0.087663054, 0.046040572, 0.0462882, -0.00010573519, -0.010467146, -0.07709419, 0.152173, 0.09813602, -0.021327294, 0.05584744, 0.040130734, -0.00064467563, -0.14109746, -0.0026743603, -0.03963436, 0.05158029, 0.011880167, -0.008452018, 0.09587823, -0.07375782, -0.070558995, 0.044198938, -0.04227796, -0.026933009, -0.033835977, -0.014811964, -0.015372265, 0.0547626, 0.033653956, -0.055505328, -0.008752807, 0.004796823, -0.07239827, -0.04276828, 0.012956009, -0.04972134, -0.034704983, -0.0835528, -0.055687666, 0.04631113, 0.05363356, 0.02901732, 0.015014432, -0.027760105, 0.06139928, 0.03282123, -0.0042268042, -0.0031610513, 0.014839815, 0.1019493, -0.056873865, -0.009099505, 0.051656768, 0.024685243, -0.10590046, -0.07014385, -0.06894493, 6.2005434e-32, 0.0859131, 0.012920234, -0.060473066, -0.11963326, -0.07676914, 0.074950956, 0.053429637, 0.02035871, -0.020423215, -0.005835581, -0.036415134, -0.0692425, 0.055407915, -0.015048473, -0.014705356, 0.00033132383, 0.01705916, -0.009166056, -0.0032017888, 0.03305532, -0.034790248, -0.009569597, 0.07824881, -0.029898897, 0.010513333, -0.05471263, -0.019414004, -0.110035025, 0.038790546, -0.03567949, -0.080986604, -0.009443597, 0.021561278, 0.0009322711, 0.019750433, -0.015624648, 0.056705832, 0.0052719144, 0.009812506, -0.029573465, 0.008139361, 0.09923312, -0.025000688, -0.019078014, -0.042461023, -0.0376757, 0.019319292, 0.085914545, -0.053519275, -0.0667761, -0.05914592, 0.029175915, -0.02626312, -0.0054403185, -0.04218989, 0.06464478, -0.0130547425, 0.029704344, -0.01509469, 0.013433415, -0.02288232, 0.061774924, 0.11015576, -0.057674132];

        let dist_xy = dot_distance(&x, &y);
        let dist_xz = dot_distance(&x, &z);

        let delta = dist_xz - dist_xy;
        let beta = delta.abs();
        assert!(beta > 0.0);

        let seed = EncryptionKey::new(dimension, beta, 2.0);
        let fx = encrypt(&seed, x.clone());
        let fy = encrypt(&seed, y.clone());
        let fz = encrypt(&seed, z.clone());

        let dist_fxy = dot_distance(&fx, &fy);
        let dist_fxz = dot_distance(&fx, &fz);

        if dist_xz > dist_xy {
            assert!(dist_fxz > dist_fxy);
        } else {
            assert!(dist_fxz < dist_fxy);
        }
    }
}

