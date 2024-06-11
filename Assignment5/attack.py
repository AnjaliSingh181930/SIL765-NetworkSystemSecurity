import torch
from model import ANNClassifier
import matplotlib.pyplot as plt
import numpy as np

class FGSM:
    def __init__(self, model, criterion, epsilon=0.3):
        self.model = model
        self.criterion = criterion
        self.epsilon = epsilon
        self.digit_examples = {i: None for i in range(10)}  # Dictionary to store per digit examples

    def apply(self, test_loader):
        self.model.eval()
        correct = 0
        total = 0
        adv_examples = []

        for images, labels in test_loader:
            images.requires_grad = True
            outputs = self.model(images)
            loss = self.criterion(outputs, labels)
            self.model.zero_grad()
            loss.backward()
            
            # Get the sign of the gradient
            data_grad = images.grad.data.sign()
            
            # perturbed_images = torch.clamp(images + self.epsilon * data_grad, 0, 1)
            
            # Perturb the input image using the gradient sign
            perturbed_images = images + self.epsilon * data_grad

            # Clip the perturbed images to ensure they remain within valid pixel range
            perturbed_images = torch.clamp(perturbed_images, 0, 1)

            # Store examples per digit
            for i in range(len(labels)):
                label = labels[i].item()
                if self.digit_examples[label] is None:
                    self.digit_examples[label] = (images[i], perturbed_images[i], data_grad[i])

            if all(v is not None for v in self.digit_examples.values()):
                break  # Break if we have collected all digits

            # Re-classify the perturbed images
            perturbed_outputs = self.model(perturbed_images)

            # Check for successful evasion
            _, perturbed_predicted = torch.max(perturbed_outputs, 1)
            total += labels.size(0)
            correct += (perturbed_predicted == labels).sum().item()

            # Save adversarial examples
            adv_examples.append(perturbed_images)

        # Plotting
        fig, axs = plt.subplots(3, 10, figsize=(15, 5))
        for i in range(10):
            orig, adv, noise = self.digit_examples[i]
            axs[0, i].imshow(orig.squeeze().detach().numpy(), cmap='gray')
            axs[1, i].imshow(adv.squeeze().detach().numpy(), cmap='gray')
            noise_norm = torch.norm(noise.squeeze()).item()
            axs[2, i].imshow(noise.squeeze().detach().numpy(), cmap='gray')
            axs[2, i].set_title(f"L2: {noise_norm:.2f}")
            
        for ax in axs.flat:
            ax.axis('off')
        plt.savefig("L1.png")
        plt.show()
        
        # Compute evasion rate
        evasion_rate = (1 - correct / total)*100
        print(f'Evasion Rate: {evasion_rate:.2f}%')

        return {"evasion_rate": evasion_rate, "adv_examples": adv_examples}

if __name__ == "__main__":

    attack_params = {
        "batch_size": 1,
        "epsilon": 0.3,
        "learning_rate": 0.01,
        "model_name": "model.pth"
    }

    # Load the trained model
    model = ANNClassifier(attack_params)
    model.load_state_dict(torch.load(attack_params["model_name"]))

    # Load the test data
    train_loader, test_loader = model.get_dataloaders()
    model.train_loader = train_loader
    model.test_loader = test_loader

    ## Attack ##

    # Attack the model on test set
    attack = FGSM(model, torch.nn.CrossEntropyLoss(), attack_params["epsilon"])
    results: dict = attack.apply(test_loader)
    
    # Extract misclassified examples
    misclassified_counts = {digit: {} for digit in range(10)}
    for i in range(10):
        adv = results["adv_examples"][i]  # Only perturbed image needed
        orig_label = i
        pred_label = torch.argmax(model.forward(adv.unsqueeze(0)), dim=1).item()
        if pred_label != orig_label:
            if pred_label not in misclassified_counts[orig_label]:
                misclassified_counts[orig_label][pred_label] = 1
            else:
                misclassified_counts[orig_label][pred_label] += 1

    # Find the most misclassified label for each digit
    most_misclassified = {digit: None for digit in range(10)}
    for digit, counts in misclassified_counts.items():
        if counts:
            most_misclassified[digit] = max(counts, key=counts.get)

    print("Most misclassified labels for each digit:")
    for digit, misclassified_label in most_misclassified.items():
        if misclassified_label is not None:
            print(f"Digit {digit} is most frequently misclassified as {misclassified_label}")
        else:
            print(f"Digit {digit} is not misclassified.")
    
    # check if the results contains a key named "adv_examples" and check each element
    # is a torch.Tensor. THIS IS IMPORTANT TO PASS THE TEST CASES!!!
    assert "adv_examples" in results.keys(), "Results should contain a key named 'adv_examples'"
    assert all([isinstance(x, torch.Tensor) for x in results["adv_examples"]]), "All elements in 'adv_examples' should be torch.Tensor"

    # check the image size should be 1x28x28
    print(results["adv_examples"][0].shape)
    assert results["adv_examples"][0].shape[1] == 1, "The image should be grayscale"
    assert results["adv_examples"][0].shape[2] == 28, "The image should be 28x28"
